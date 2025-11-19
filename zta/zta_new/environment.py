"""
Simulation environment orchestrating the adaptive Zero-Trust policy.
"""

from __future__ import annotations

import random
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

import networkx as nx
import pandas as pd

from .dataset_catalog import DATASET_CATALOG, SUPPORTED_ATTACKS
from .malicious import AttackProfile
from .node import ZTANode
from .policy import GNNRLPolicy
from .task import TaskOutcome, TaskSpec


@dataclass
class SimulationResult:
    dataset_name: str
    description: str
    task_outcomes: List[TaskOutcome]
    node_snapshots: Dict[str, Dict[str, float]]
    node_histories: Dict[str, Dict[str, List[float]]]
    attack_events: List[Dict[str, float]]
    policy_history: Dict[str, List[float]]
    metrics: Optional[Dict[str, Any]] = None


class ZTASimulation:
    def __init__(self, dataset: Dict, rng: Optional[random.Random] = None) -> None:
        self.dataset = dataset
        self.rng = rng or random.Random(dataset.get("seed", 1234))
        self.graph = self._build_graph(dataset["topology"])
        self.nodes = self._build_nodes(dataset)
        self.policy = GNNRLPolicy(self.rng)
        self.attack_events: List[Dict[str, float]] = []

    # ------------------------------------------------------------------

    def _build_graph(self, topology: Dict) -> nx.Graph:
        graph = nx.Graph()
        for node in topology["nodes"]:
            graph.add_node(node["name"], role=node["role"])
        for src, dst, attrs in topology["links"]:
            graph.add_edge(src, dst, **attrs)
        return graph

    def _build_nodes(self, dataset: Dict) -> Dict[str, ZTANode]:
        nodes: Dict[str, ZTANode] = {}
        malicious_profiles = dataset.get("malicious_profiles", {})

        for node_spec in dataset["topology"]["nodes"]:
            name = node_spec["name"]
            attack_profile = None
            is_malicious = node_spec.get("is_malicious", False)
            profile_dict = malicious_profiles.get(name)
            if is_malicious or profile_dict:
                if profile_dict is None:
                    raise ValueError(f"Node '{name}' flagged malicious but no profile defined for dataset '{dataset['name']}'.")
                if profile_dict["attack_type"] not in SUPPORTED_ATTACKS:
                    raise ValueError(f"Unsupported attack type '{profile_dict['attack_type']}' for node '{name}'.")
                attack_profile = AttackProfile(node_name=name, **profile_dict)
                is_malicious = True

            nodes[name] = ZTANode(
                name=name,
                role=node_spec["role"],
                cpu_capacity=float(node_spec["cpu"]),
                memory_capacity=float(node_spec["memory"]),
                initial_trust=float(node_spec["initial_trust"]),
                is_malicious=is_malicious,
                attack_profile=attack_profile,
            )
        return nodes

    def _choose_source_node(self) -> str:
        candidates = [n for n in self.nodes.values() if n.role != "cloud"]
        return self.rng.choice(candidates).name

    def _generate_tasks(self) -> List[TaskSpec]:
        if "task_source" in self.dataset:
            return self._load_tasks_from_dataset(self.dataset["task_source"])

        # Fallback synthetic generator (used only when historical params supplied)
        params = self.dataset["task_params"]
        num_tasks = params["num_tasks"]
        arrivals = sorted(self.rng.uniform(0, num_tasks / 3) for _ in range(num_tasks))
        criticalities = list(params["criticality_split"].items())
        sensitivities = list(params["sensitivity_split"].items())

        def weighted_choice(options):
            total = sum(weight for _, weight in options)
            roll = self.rng.uniform(0, total)
            upto = 0.0
            for value, weight in options:
                upto += weight
                if roll <= upto:
                    return value
            return options[-1][0]

        tasks: List[TaskSpec] = []
        for task_id, arrival in enumerate(arrivals):
            task = TaskSpec(
                task_id=task_id,
                arrival_time=arrival,
                size_mb=self.rng.uniform(*params["size_range"]),
                cycles_per_bit=self.rng.uniform(*params["cycles_per_bit"]),
                deadline=self.rng.uniform(*params["deadline_range"]),
                src=self._choose_source_node(),
                criticality=weighted_choice(criticalities),
                sensitivity=weighted_choice(sensitivities),
            )
            tasks.append(task)
        return sorted(tasks, key=lambda t: t.arrival_time)

    def _load_tasks_from_dataset(self, task_cfg: Dict) -> List[TaskSpec]:
        path = Path(task_cfg["path"])
        if not path.exists():
            raise FileNotFoundError(f"Task dataset '{path}' not found.")

        df = pd.read_csv(path)
        time_col = task_cfg.get("time_column", "GenerationTime")
        size_col = task_cfg.get("size_column", "TaskSize")
        cycles_col = task_cfg.get("cycles_column", "CyclesPerBit")
        deadline_col = task_cfg.get("deadline_column", "DDL")
        id_col = task_cfg.get("id_column", "TaskID")

        src_col = task_cfg.get("src_column")
        if task_cfg.get("filter_src_in") and src_col in df.columns:
            df = df[df[src_col].isin(task_cfg["filter_src_in"])]

        df = df.sort_values(time_col).reset_index(drop=True)

        nodes_by_role = self._nodes_by_role()
        tasks: List[TaskSpec] = []
        for _, row in df.iterrows():
            src_name = self._resolve_task_source(row, task_cfg, nodes_by_role)
            if src_name is None:
                continue

            arrival = float(row[time_col])
            size_divisor = task_cfg.get("size_divisor", 1.0)
            size_mb = float(row[size_col]) / size_divisor
            cycles_per_bit = float(row[cycles_col]) * task_cfg.get("cycles_multiplier", 1.0)
            deadline = float(row[deadline_col]) * task_cfg.get("deadline_multiplier", 1.0)
            bitrate = None
            bitrate_col = task_cfg.get("bitrate_column")
            if bitrate_col and bitrate_col in row and not pd.isna(row[bitrate_col]):
                bitrate = float(row[bitrate_col]) * task_cfg.get("bitrate_multiplier", 1.0)

            criticality = self._compute_criticality(deadline, row, task_cfg)
            sensitivity = self._compute_sensitivity(size_mb, row, task_cfg)
            metadata = {
                col: row[col]
                for col in task_cfg.get("metadata_columns", [])
                if col in row
            }
            metadata["raw_task_size"] = float(row[size_col])
            metadata["raw_cycles_per_bit"] = float(row[cycles_col])
            metadata["size_divisor"] = size_divisor
            metadata["data_bits"] = float(row[size_col]) * task_cfg.get("size_to_bits", 8.0)
            metadata["bitrate_multiplier"] = task_cfg.get("bitrate_multiplier", 1.0)

            task = TaskSpec(
                task_id=int(row.get(id_col, len(tasks))),
                arrival_time=arrival,
                size_mb=size_mb,
                cycles_per_bit=cycles_per_bit,
                deadline=deadline,
                src=src_name,
                criticality=criticality,
                sensitivity=sensitivity,
                trans_bit_rate=bitrate,
                metadata=metadata,
            )
            tasks.append(task)

        return sorted(tasks, key=lambda t: t.arrival_time)

    def _nodes_by_role(self) -> Dict[str, List[str]]:
        nodes_by_role: Dict[str, List[str]] = {}
        for node in self.nodes.values():
            nodes_by_role.setdefault(node.role, []).append(node.name)
        return nodes_by_role

    def _resolve_task_source(self, row, task_cfg: Dict, nodes_by_role: Dict[str, List[str]]) -> Optional[str]:
        src_col = task_cfg.get("src_column")
        if src_col and src_col in row and not pd.isna(row[src_col]):
            raw = str(row[src_col])
            if raw in self.nodes:
                return raw

        device_col = task_cfg.get("device_column")
        if device_col and device_col in row and not pd.isna(row[device_col]):
            device_value = str(row[device_col])
            roles_map = task_cfg.get("allowed_roles_map", {})
            candidate_roles = roles_map.get(device_value, [])
            candidates = [name for role in candidate_roles for name in nodes_by_role.get(role, [])]
            if candidates:
                index = abs(hash((device_value, row.get(task_cfg.get("id_column", "TaskID"), 0)))) % len(candidates)
                return candidates[index]

        allowed_roles = task_cfg.get("allowed_roles")
        candidates = [
            name
            for role, names in nodes_by_role.items()
            if not allowed_roles or role in allowed_roles
            for name in names
        ]
        if not candidates:
            return None

        if src_col and src_col in row and not pd.isna(row[src_col]):
            raw = str(row[src_col])
            index = abs(hash(raw)) % len(candidates)
            return candidates[index]

        return self.rng.choice(candidates)

    def _compute_criticality(self, deadline: float, row, task_cfg: Dict) -> str:
        thresholds = task_cfg.get("criticality_thresholds")
        if thresholds and len(thresholds) >= 2:
            high_thr, medium_thr = thresholds[0], thresholds[1]
        else:
            high_thr, medium_thr = 30.0, 70.0

        if deadline <= high_thr:
            return "high"
        if deadline <= medium_thr:
            return "medium"
        return "low"

    def _compute_sensitivity(self, size_mb: float, row, task_cfg: Dict) -> str:
        data_type_col = task_cfg.get("data_type_column")
        sensitivity_map = task_cfg.get("sensitivity_map", {})
        if data_type_col and data_type_col in row and not pd.isna(row[data_type_col]):
            label = sensitivity_map.get(str(row[data_type_col]), sensitivity_map.get("default"))
            if label:
                return label

        rules = task_cfg.get("size_sensitivity", [])
        for rule in rules:
            max_threshold = rule.get("max")
            if max_threshold is not None and size_mb <= max_threshold:
                return rule["label"]
        if rules:
            return rules[-1]["label"]
        return "confidential"

    # ------------------------------------------------------------------

    def _ensemble_state(self, current_task: TaskSpec) -> Dict[str, str]:
        avg_load = sum(node.running_load for node in self.nodes.values()) / max(1, len(self.nodes))
        max_anomaly = max(node.anomaly_index for node in self.nodes.values())

        system_load = "normal"
        if avg_load > 0.8:
            system_load = "high"
        elif avg_load < 0.3:
            system_load = "low"

        threat_level = "alert" if max_anomaly > 0.6 else "normal"
        if any(node.quarantine for node in self.nodes.values()):
            threat_level = "alert"

        return {
            "system_load": system_load,
            "threat_level": threat_level,
            "task_criticality": current_task.criticality,
        }

    def _compute_route_cost(self, src: str, dst: str) -> Tuple[float, int, float]:
        if src == dst:
            return 0.0, 0, float("inf")

        try:
            path = nx.shortest_path(self.graph, source=src, target=dst, weight="latency")
        except nx.NetworkXNoPath:
            # fallback: treat as large latency to encourage reroute by RL updates
            latency = 250.0
            return latency, 1, 10.0

        latency = 0.0
        hop_count = 0
        min_bandwidth = float("inf")
        for u, v in zip(path[:-1], path[1:]):
            edge = self.graph.edges[u, v]
            latency += edge.get("latency", 10.0)
            bandwidth = edge.get("bandwidth", 100.0)
            min_bandwidth = min(min_bandwidth, bandwidth)
            hop_count += 1
        return latency, hop_count, min_bandwidth

    # ------------------------------------------------------------------

    def run(self) -> SimulationResult:
        tasks = self._generate_tasks()
        outcomes: List[TaskOutcome] = []
        # For detection metrics and quarantine lifecycle
        first_quarantine_task: Dict[str, int] = {}
        # Quarantine lifecycle parameters (tuned to cut FPs across datasets)
        TEMP_TTL = 80   # shorter temp hold to reduce benign downtime
        ESCALATE_AFTER = 3  # require three independent temp events to escalate
        ESCALATE_TRUST_MAX = 0.52
        ESCALATE_ANOMALY_MIN = 0.65

        # Additional gating using neighbour consensus to reduce FPs.
        QUAR_TRUST_GATE = 0.50
        QUAR_ANOM_GATE = 0.60
        QUAR_ANOM_EXTREME = 0.85
        NEIGHBOR_TRUST_GATE = 0.70
        NEIGHBOR_ANOM_GATE = 0.45
        temp_quarantine_durations: List[int] = []
        reroutes_by_node: Dict[str, int] = {}
        reroutes_total = 0

        for task in tasks:
            # Quarantine lifecycle maintenance for all nodes
            for node in self.nodes.values():
                if node.quarantine and not node.quarantine_permanent:
                    if node.quarantine_ttl > 0:
                        node.quarantine_ttl -= 1
                    # Escalate quickly on strong evidence
                    if node.compute_final_trust() <= ESCALATE_TRUST_MAX or node.anomaly_index >= ESCALATE_ANOMALY_MIN:
                        node.quarantine_permanent = True
                        node.quarantine_ttl = 0
                        self.attack_events.append(
                            {
                                "task_id": task.task_id,
                                "node": node.name,
                                "event": "quarantine_permanent",
                                "anomaly": node.anomaly_index,
                                "final_trust": node.compute_final_trust(),
                            }
                        )
                    elif node.quarantine_ttl == 0:
                        # Release if TTL expired and risk subsided (more conservative)
                        if node.anomaly_index < 0.2 and node.compute_final_trust() > 0.75:
                            node.quarantine = False
                            if getattr(node, "quarantine_since_task", None) is not None:
                                duration = max(0, task.task_id - node.quarantine_since_task)
                                temp_quarantine_durations.append(duration)
                                node.quarantine_since_task = None
                            self.attack_events.append(
                                {
                                    "task_id": task.task_id,
                                    "node": node.name,
                                    "event": "quarantine_release",
                                    "anomaly": node.anomaly_index,
                                    "final_trust": node.compute_final_trust(),
                                }
                            )

            system_state = self._ensemble_state(task)

            # Attempt selection, retry if quarantine prevents processing.
            attempts = 0
            selected_node = None
            selected_action = "test_task_logging"
            feature_vec = None
            base_features = None
            while attempts < len(self.nodes):
                node, action, feature_vec, base_features = self.policy.select_node_and_action(
                    self.graph, self.nodes, system_state
                )
                if action == "quarantine":
                    # Neighbour-consensus gate: require support from neighbours
                    nbrs = list(self.graph.neighbors(node.name))
                    if nbrs:
                        nbr_trust = [self.nodes[n].compute_final_trust() for n in nbrs]
                        nbr_anom = [self.nodes[n].anomaly_index for n in nbrs]
                        # Guard against unexpected empty lists
                        avg_nbr_trust = sum(nbr_trust) / max(1, len(nbr_trust))
                        avg_nbr_anom = sum(nbr_anom) / max(1, len(nbr_anom))
                    else:
                        avg_nbr_trust = 1.0
                        avg_nbr_anom = 0.0

                    strong_self = (base_features["final_trust"] <= QUAR_TRUST_GATE and base_features["anomaly"] >= QUAR_ANOM_GATE) or (base_features["anomaly"] >= QUAR_ANOM_EXTREME)
                    neighbor_support = (avg_nbr_trust <= NEIGHBOR_TRUST_GATE) or (avg_nbr_anom >= NEIGHBOR_ANOM_GATE)

                    if not (strong_self and neighbor_support):
                        # Downgrade to monitored full assignment instead of quarantine
                        self.attack_events.append(
                            {
                                "task_id": task.task_id,
                                "node": node.name,
                                "event": "quarantine_downgraded",
                                "anomaly": base_features["anomaly"],
                                "final_trust": base_features["final_trust"],
                            }
                        )
                        selected_node = node
                        selected_action = "full_assignment_monitoring"
                        break
                    # Apply temporary quarantine; manage lifecycle in env
                    if not node.quarantine:
                        node.quarantine = True
                        node.quarantine_ttl = TEMP_TTL
                        node.quarantine_count += 1
                        node.quarantine_since_task = task.task_id
                        if node.name not in first_quarantine_task:
                            first_quarantine_task[node.name] = task.task_id
                        self.attack_events.append(
                            {
                                "task_id": task.task_id,
                                "node": node.name,
                                "event": "quarantine_temp",
                                "anomaly": base_features["anomaly"],
                                "final_trust": base_features["final_trust"],
                            }
                        )
                    # Count this as a reroute away from the risky node
                    reroutes_total += 1
                    reroutes_by_node[node.name] = reroutes_by_node.get(node.name, 0) + 1
                    # Escalate promptly if repeated or strong signal
                    if (
                        node.quarantine_count >= ESCALATE_AFTER
                        or base_features["final_trust"] <= ESCALATE_TRUST_MAX
                        or base_features["anomaly"] >= ESCALATE_ANOMALY_MIN
                    ):
                        node.quarantine_permanent = True
                        node.quarantine_ttl = 0
                        self.attack_events.append(
                            {
                                "task_id": task.task_id,
                                "node": node.name,
                                "event": "quarantine_permanent",
                                "anomaly": base_features["anomaly"],
                                "final_trust": base_features["final_trust"],
                            }
                        )
                    attempts += 1
                    continue
                # If the chosen node is already permanently quarantined, log reroute
                if node.quarantine and node.quarantine_permanent:
                    self.attack_events.append(
                        {
                            "task_id": task.task_id,
                            "node": node.name,
                            "event": "reroute_permanent_quarantine",
                            "anomaly": base_features["anomaly"],
                            "final_trust": base_features["final_trust"],
                        }
                    )
                    reroutes_total += 1
                    reroutes_by_node[node.name] = reroutes_by_node.get(node.name, 0) + 1
                    attempts += 1
                    continue

                selected_node = node
                selected_action = action
                break

            if selected_node is None:
                # Fallback: assign to highest trust node even if malicious to avoid dropping workloads.
                selected_node = max(self.nodes.values(), key=lambda n: n.compute_final_trust())
                selected_action = "partial_assignment"
                feature_vec, base_features = self.policy.feature_vector_for(selected_node, self.graph)

            path_latency, hop_count, path_bandwidth = self._compute_route_cost(task.src, selected_node.name)
            raw_size = task.metadata.get("raw_task_size")
            size_divisor = task.metadata.get("size_divisor", 1.0)
            raw_cycles = task.metadata.get("raw_cycles_per_bit", task.cycles_per_bit)
            if raw_size is None:
                raw_size = task.size_mb * size_divisor
            data_bits = task.metadata.get("data_bits")
            if data_bits is None:
                data_bits = raw_size * 8.0

            cpu_freq = max(100.0, selected_node.cpu_capacity)  # consistent with RayCloudSim units
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

            outcome = selected_node.simulate_execution(
                task=task,
                action=selected_action,
                base_transmission=base_transmission,
                base_execution=base_execution,
                rng=self.rng,
            )

            outcomes.append(outcome)

            # Policy update with next-state rollouts.
            next_state = self._ensemble_state(task)
            next_feature_bank: List = []
            for candidate in self.nodes.values():
                if candidate.quarantine:
                    continue
                vec, _ = self.policy.feature_vector_for(candidate, self.graph)
                next_feature_bank.append(vec)
            self.policy.update(feature_vec, outcome.reward, next_feature_bank)

        node_snapshots = {}
        node_histories = {}
        for name, node in self.nodes.items():
            node_snapshots[name] = {
                "final_trust": node.compute_final_trust(),
                "anomaly": node.anomaly_index,
                "success_rate": node.performance_trust,
                "quarantine": 1.0 if node.quarantine else 0.0,
                "quarantine_permanent": 1.0 if node.quarantine_permanent else 0.0,
                "malicious": 1.0 if node.is_malicious else 0.0,
            }
            node_histories[name] = {
                "trust": list(node.trust_history),
                "final_trust": list(node.final_trust_history),
                "actions": list(node.action_history),
                "latency": list(node.latency_history),
            }

        # Detection metrics using permanent quarantine as the positive prediction
        tp = sum(1 for n in self.nodes.values() if n.is_malicious and n.quarantine_permanent)
        fp = sum(1 for n in self.nodes.values() if (not n.is_malicious) and n.quarantine_permanent)
        tn = sum(1 for n in self.nodes.values() if (not n.is_malicious) and (not n.quarantine_permanent))
        fn = sum(1 for n in self.nodes.values() if n.is_malicious and (not n.quarantine_permanent))
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
        f1 = (2 * precision * recall) / max(1e-9, (precision + recall)) if (precision + recall) > 0 else 0.0
        malicious_names = [name for name, n in self.nodes.items() if n.is_malicious]
        ttd_values = [first_quarantine_task.get(name) for name in malicious_names if first_quarantine_task.get(name) is not None]
        mean_ttd = (sum(ttd_values) / len(ttd_values)) if ttd_values else -1
        percent_capacity_quarantined = (
            sum(n.cpu_capacity for n in self.nodes.values() if n.quarantine_permanent)
            / max(1.0, sum(n.cpu_capacity for n in self.nodes.values()))
        )
        # Extra metrics: specificity and MCC, average temp quarantine dwell
        specificity = tn / max(1, tn + fp)
        # Guard MCC denominator and reuse the guarded value in division
        raw_denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
        if raw_denom > 0:
            mcc = ((tp * tn) - (fp * fn)) / (float(raw_denom) ** 0.5)
        else:
            mcc = 0.0

        metrics = {
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "specificity": specificity,
            "mcc": mcc,
            "mean_time_to_first_quarantine": mean_ttd,
            "percent_capacity_quarantined": percent_capacity_quarantined,
            "temp_quarantine_events": sum(1 for e in self.attack_events if e["event"] == "quarantine_temp"),
            "permanent_quarantine_events": sum(1 for e in self.attack_events if e["event"] == "quarantine_permanent"),
            "quarantine_releases": sum(1 for e in self.attack_events if e["event"] == "quarantine_release"),
            "avg_temp_quarantine_dwell": (sum(temp_quarantine_durations) / len(temp_quarantine_durations)) if temp_quarantine_durations else -1,
            "reroutes_total": reroutes_total,
            "reroutes_per_task": reroutes_total / max(1, len(tasks)),
            "reroutes_by_node": reroutes_by_node,
        }

        return SimulationResult(
            dataset_name=self.dataset["name"],
            description=self.dataset["description"],
            task_outcomes=outcomes,
            node_snapshots=node_snapshots,
            node_histories=node_histories,
            attack_events=self.attack_events,
            policy_history=self.policy.history,
            metrics=metrics,
        )


def run_dataset_by_name(name: str) -> SimulationResult:
    for dataset in DATASET_CATALOG:
        if dataset["name"] == name:
            return ZTASimulation(dataset).run()
    raise ValueError(f"Unknown dataset '{name}'. Valid options: {[d['name'] for d in DATASET_CATALOG]}")


__all__ = ["ZTASimulation", "SimulationResult", "run_dataset_by_name"]
