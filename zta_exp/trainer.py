"""
GNN-RL training and evaluation pipeline for ZTA experiments.

Implements DQN-style training over directed full topologies with Zero-Trust
guardrail masks and optional decide_action veto.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np

# tqdm progress bars (fallback to no-op if not available)
try:
    from tqdm import tqdm, trange  # type: ignore
except Exception:  # pragma: no cover
    def tqdm(iterable=None, total=None, desc=None, ncols=80, leave=True):  # type: ignore
        return iterable if iterable is not None else range(total or 0)
    def trange(n, **kwargs):  # type: ignore
        return range(n)

from .assignment_matrix import decide_action
from .dataset_catalog import DATASET_CATALOG
from .environment import SimulationResult, ZTASimulation
from .masks import ACTIONS, build_zt_masks, post_veto
# Lazy import of GNN DQN components to avoid hard dependency when running rule-only
ReplayBuffer = Transition = ZTADQNPolicy = None  # type: ignore


def _node_order(env: ZTASimulation) -> Tuple[List[str], Dict[str, int]]:
    order = sorted(env.nodes.keys())
    mapping = {name: i for i, name in enumerate(order)}
    return order, mapping


def _graph_edges(env: ZTASimulation, name_to_idx: Dict[str, int]) -> List[Tuple[int, int]]:
    edges: List[Tuple[int, int]] = []
    for u, v in env.graph.edges():
        if u in name_to_idx and v in name_to_idx:
            edges.append((name_to_idx[u], name_to_idx[v]))
    return edges


def _state(env: ZTASimulation, task, node_names: List[str]) -> Tuple[List[Dict[str, float]], Dict[str, str]]:
    feats = [env.nodes[name].feature_vector(env.graph) for name in node_names]
    system_state = env._ensemble_state(task)  # type: ignore[attr-defined]
    return feats, system_state


def _apply_action(env: ZTASimulation, node_name: str, action: str, task) -> Tuple[Any, float, float]:
    # Compute path & baselines using environment helpers
    path_latency, hop_count, path_bandwidth = env._compute_route_cost(task.src, node_name)  # type: ignore[attr-defined]
    raw_size = task.metadata.get("raw_task_size")
    size_divisor = task.metadata.get("size_divisor", 1.0)
    raw_cycles = task.metadata.get("raw_cycles_per_bit", task.cycles_per_bit)
    if raw_size is None:
        raw_size = task.size_mb * size_divisor
    data_bits = task.metadata.get("data_bits")
    if data_bits is None:
        data_bits = raw_size * 8.0

    node = env.nodes[node_name]
    cpu_freq = max(100.0, node.cpu_capacity)
    base_execution = (raw_size * raw_cycles) / cpu_freq
    base_transmission = path_latency
    effective_rate = None
    if task.trans_bit_rate:
        effective_rate = task.trans_bit_rate
    if path_bandwidth and path_bandwidth != float("inf"):
        effective_rate = path_bandwidth if effective_rate is None else min(effective_rate, path_bandwidth)
    if effective_rate and hop_count > 0:
        base_transmission += (data_bits / max(1.0, effective_rate)) * hop_count
    elif hop_count > 0:
        base_transmission += (data_bits / 1_000_000.0) * hop_count

    prev_trust = node.compute_final_trust()
    outcome = node.simulate_execution(
        task=task,
        action=action,
        base_transmission=base_transmission,
        base_execution=base_execution,
        rng=env.rng,
    )
    post_trust = node.compute_final_trust()
    return outcome, prev_trust, post_trust


def _shape_reward(outcome, prev_trust: float, post_trust: float, chosen_action: str, decide_action_label: str) -> float:
    success_flag = 1.0 if outcome.success else 0.0
    latency_normalized = 0.0
    if outcome.latency > 0 and getattr(outcome, "task_id", None) is not None:
        # Normalize by execution+deadline proxy if available
        # We use a conservative denominator to keep stability
        denom = max(1.0, outcome.execution_time + outcome.transmission_time)
        latency_normalized = min(1.0, outcome.latency / denom)
    trust_drop_penalty = max(0.0, float(prev_trust - post_trust))
    zt_compliance_bonus = 1.0 if chosen_action == decide_action_label else 0.0
    quarantine_cost = 1.0 if chosen_action == "quarantine" else 0.0
    reward = (
        +1.0 * success_flag
        - 0.5 * latency_normalized
        - 0.2 * trust_drop_penalty
        + 0.3 * zt_compliance_bonus
        - 0.1 * quarantine_cost
    )
    return float(reward)


@dataclass
class EvalMetrics:
    success_rate: float
    avg_latency: float
    detections: int
    false_positives: int
    quarantine_latency: float
    reward_variance: float
    veto_frequency: float


def train_and_eval(
    mode: str = "hybrid",
    train_datasets: Sequence[str] = ("topo4mec_milan_city", "topo4mec_25n50e"),
    test_datasets: Sequence[str] = ("topo4mec_50n50e", "pakistan_tuple30k"),
    num_episodes: int = 1,
    batch_size: int = 64,
    output_root: str = "logs/zta_new",
) -> Dict[str, Dict[str, Any]]:
    """
    Train a DQN policy with GNN encoder (if mode is pure or hybrid), then evaluate
    across requested datasets in the selected mode.
    mode ∈ {"rule_only", "pure", "hybrid"}
    Returns a mapping of dataset → {result, metrics}.
    """
    assert mode in {"rule_only", "pure", "hybrid"}

    # Helper to get dataset entry by name
    def ds(name: str) -> Dict:
        for d in DATASET_CATALOG:
            if d["name"] == name:
                return d
        raise ValueError(f"Unknown dataset '{name}'.")

    results: Dict[str, Dict[str, Any]] = {}

    policy = None
    buffer = None
    if mode in {"pure", "hybrid"}:
        # Import policy components lazily
        from .policy_gnn import ReplayBuffer as _RB, Transition as _TR, ZTADQNPolicy as _POL
        global ReplayBuffer, Transition, ZTADQNPolicy
        ReplayBuffer, Transition, ZTADQNPolicy = _RB, _TR, _POL
        # Build initial env to size the model
        env0 = ZTASimulation(ds(train_datasets[0]))
        node_names, name_to_idx = _node_order(env0)
        tasks = env0._generate_tasks()
        feats, _ = _state(env0, tasks[0], node_names)
        in_dim = len(feats[0])
        policy = ZTADQNPolicy(in_dim=in_dim, num_actions=len(ACTIONS))
        buffer = ReplayBuffer(capacity=50_000)

        # Train across train datasets
        for dname in train_datasets:
            env = ZTASimulation(ds(dname))
            node_names, name_to_idx = _node_order(env)
            edges = _graph_edges(env, name_to_idx)
            for ep in trange(num_episodes, desc=f"train:{dname} episodes", ncols=80):
                tasks = env._generate_tasks()
                veto_count = 0
                rewards = []
                for t_idx, task in enumerate(tqdm(tasks, desc=f"train:{dname} ep {ep+1}/{num_episodes}", ncols=80, leave=False)):
                    feats, system_state = _state(env, task, node_names)
                    if mode == "pure":
                        mask = np.ones((len(feats), len(ACTIONS)), dtype=np.float32)
                    else:
                        mask = build_zt_masks(feats, system_state)

                    # Select action
                    (v_idx, a_idx), _aux = policy.select(feats, edges, system_state, epsilon=max(0.02, 0.2 * (0.99 ** (ep * 10 + t_idx // 200))))
                    chosen_action = ACTIONS[a_idx]
                    # Veto only in hybrid mode
                    decide_label = decide_action(feats[v_idx], system_state)
                    if mode == "hybrid":
                        post = post_veto(feats[v_idx], system_state, chosen_action)
                        if decide_label == "quarantine" and post != "quarantine":
                            veto_count += 1
                            post = "quarantine"
                        chosen_action = post

                    node_name = node_names[v_idx]
                    outcome, prev_trust, post_trust = _apply_action(env, node_name, chosen_action, task)
                    shaped_reward = _shape_reward(outcome, prev_trust, post_trust, chosen_action, decide_label)
                    rewards.append(shaped_reward)

                    # Next state
                    feats_next, system_state_next = _state(env, task, node_names)
                    if mode == "pure":
                        mask_next = np.ones((len(feats_next), len(ACTIONS)), dtype=np.float32)
                    else:
                        mask_next = build_zt_masks(feats_next, system_state_next)

                    # Buffer + learn
                    X, EI = policy.build_graph_tensors(feats, edges)
                    nX, nEI = policy.build_graph_tensors(feats_next, edges)
                    tr = Transition(
                        x=X,
                        edge_index=EI,
                        mask=policy.build_graph_tensors(feats, edges)[0].new_tensor(mask),
                        index_pair=(v_idx, a_idx),
                        reward=float(shaped_reward),
                        next_x=nX,
                        next_edge_index=nEI,
                        next_mask=policy.build_graph_tensors(feats_next, edges)[0].new_tensor(mask_next),
                        done=(t_idx == len(tasks) - 1),
                    )
                    buffer.add(tr)  # type: ignore[arg-type]
                    if len(buffer) > batch_size:
                        batch = buffer.sample(batch_size)
                        policy.learn(batch)

                # Optionally log episode stats (omitted here to keep concise)

    # Evaluate across test datasets (or all datasets if rule-only)
    eval_sets = test_datasets if mode in {"pure", "hybrid"} else list(d["name"] for d in DATASET_CATALOG)
    for dname in eval_sets:
        env = ZTASimulation(ds(dname))
        node_names, name_to_idx = _node_order(env)
        edges = _graph_edges(env, name_to_idx)
        tasks = env._generate_tasks()

        outcomes = []
        attack_events: List[Dict[str, float]] = []
        malicious_names = {n for n, obj in env.nodes.items() if obj.is_malicious}
        first_quarantine_idx: Dict[str, int] = {}
        veto_count = 0
        reward_history: List[float] = []

        for t_idx, task in enumerate(tqdm(tasks, desc=f"eval:{dname}", ncols=80)):
            feats, system_state = _state(env, task, node_names)

            if mode == "rule_only":
                # Choose node by max trust; action by rule
                candidate_idx = int(np.argmax([f["final_trust"] for f in feats]))
                chosen_action = decide_action(feats[candidate_idx], system_state)
                node_name = node_names[candidate_idx]
            else:
                # RL selection
                (v_idx, a_idx), _aux = policy.select(feats, edges, system_state, epsilon=0.0)  # type: ignore[arg-type]
                chosen_action = ACTIONS[a_idx]
                decide_label = decide_action(feats[v_idx], system_state)
                if mode == "hybrid":
                    post = post_veto(feats[v_idx], system_state, chosen_action)
                    if decide_label == "quarantine" and post != "quarantine":
                        veto_count += 1
                        post = "quarantine"
                    chosen_action = post
                node_name = node_names[v_idx]

            prev_trust = env.nodes[node_name].compute_final_trust()
            outcome, prev_trust, post_trust = _apply_action(env, node_name, chosen_action, task)
            outcomes.append(outcome)
            dl = decide_action(feats[node_names.index(node_name)], system_state)
            reward_history.append(_shape_reward(outcome, prev_trust, post_trust, chosen_action, dl))

            if chosen_action == "quarantine":
                attack_events.append({
                    "task_id": task.task_id,
                    "node": node_name,
                    "event": "quarantine",
                    "anomaly": feats[node_names.index(node_name)]["anomaly"],
                    "final_trust": feats[node_names.index(node_name)]["final_trust"],
                })
                if node_name in malicious_names and node_name not in first_quarantine_idx:
                    first_quarantine_idx[node_name] = t_idx

        # Metrics
        success_rate = sum(o.success for o in outcomes) / max(1, len(outcomes))
        avg_latency = sum(o.latency for o in outcomes) / max(1, len(outcomes))
        detections = sum(1 for ev in attack_events if ev["event"] == "quarantine" and ev["node"] in malicious_names)
        false_positives = sum(1 for ev in attack_events if ev["event"] == "quarantine" and ev["node"] not in malicious_names)
        quarantine_latency = float(np.mean(list(first_quarantine_idx.values())) if first_quarantine_idx else 0.0)
        reward_variance = float(np.var(reward_history)) if reward_history else 0.0
        veto_frequency = float(veto_count) / max(1, len(outcomes))

        # Compose result for visualization
        node_snapshots = {}
        node_histories = {}
        for name, node in env.nodes.items():
            node_snapshots[name] = {
                "final_trust": node.compute_final_trust(),
                "anomaly": node.anomaly_index,
                "success_rate": node.performance_trust,
                "quarantine": 1.0 if node.quarantine else 0.0,
            }
            node_histories[name] = {
                "trust": list(node.trust_history),
                "actions": list(node.action_history),
                "latency": list(node.latency_history),
            }

        sim_result = SimulationResult(
            dataset_name=env.dataset["name"],
            description=env.dataset["description"],
            task_outcomes=outcomes,
            node_snapshots=node_snapshots,
            node_histories=node_histories,
            attack_events=attack_events,
            policy_history={"reward": reward_history},
        )

        metrics = EvalMetrics(
            success_rate=success_rate,
            avg_latency=avg_latency,
            detections=detections,
            false_positives=false_positives,
            quarantine_latency=quarantine_latency,
            reward_variance=reward_variance,
            veto_frequency=veto_frequency,
        )

        results[dname] = {"result": sim_result, "metrics": metrics.__dict__}

    return results


__all__ = ["train_and_eval"]
