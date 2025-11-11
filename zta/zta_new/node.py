"""
Node abstraction with adaptive trust accounting for the Zero-Trust RL environment.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

from collections import deque

from .malicious import AttackProfile, MaliciousLogic
from .task import TaskOutcome, TaskSpec


WINDOW = 32  # sliding window for trust/anomaly computation
# Anomaly hyperparameters (identity-agnostic)
OSC_DELTA = 0.04   # min change to count as oscillation flip
CP_DELTA = 0.08    # min jump to count as change point
SIGMA_MAX = 0.25   # stdev normalization cap for variance score


@dataclass
class ZTANode:
    name: str
    role: str
    cpu_capacity: float  # abstract GHz equivalent
    memory_capacity: float  # GB
    initial_trust: float
    is_malicious: bool = False
    attack_profile: Optional[AttackProfile] = None

    success_count: int = 0
    failure_count: int = 0
    running_load: float = 0.0
    anomaly_index: float = 0.0
    trust_history: Deque[float] = field(default_factory=lambda: deque(maxlen=WINDOW))
    action_history: Deque[str] = field(default_factory=lambda: deque(maxlen=WINDOW))
    latency_history: Deque[float] = field(default_factory=lambda: deque(maxlen=WINDOW))
    quarantine: bool = False
    monitored: bool = False
    # Quarantine lifecycle controls (managed by environment).
    quarantine_permanent: bool = False
    quarantine_ttl: int = 0
    quarantine_count: int = 0
    quarantine_since_task: Optional[int] = None

    def __post_init__(self) -> None:
        # Normalise initial trust boundaries and warm-up histories to avoid cold 0s.
        base_trust = max(0.05, min(0.95, self.initial_trust))
        for _ in range(5):
            self.trust_history.append(base_trust)
            self.latency_history.append(1.0)
            self.action_history.append("bootstrap")

    # ---- Zero Trust metrics -------------------------------------------------

    @property
    def performance_trust(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total

    @property
    def behavior_trust(self) -> float:
        util_penalty = min(1.0, max(0.0, self.running_load))
        latency_penalty = min(1.0, sum(self.latency_history) / len(self.latency_history) / 75.0)
        return max(0.0, 1.0 - 0.5 * util_penalty - 0.5 * latency_penalty)

    @property
    def feedback_trust(self) -> float:
        if not self.trust_history:
            return 0.5
        return sum(self.trust_history) / len(self.trust_history)

    def compute_final_trust(self) -> float:
        # Trust fusion aligned with paper-inspired formulation (bounded and anomaly-aware)
        fused = 0.4 * self.performance_trust + 0.3 * self.feedback_trust + 0.3 * self.behavior_trust
        denom = 1.0 + max(0.0, self.anomaly_index)
        return max(0.0, min(1.0, fused / denom))

    def update_anomaly(self, new_trust: float) -> None:
        """
        Adaptive anomaly index using softmax‑weighted combination of:
        - Oscillation (trend flips),
        - Variance (normalized stdev),
        - Change points (large jumps).
        """
        hist = list(self.trust_history)
        if len(hist) < 6:
            self.anomaly_index = 0.0
            return

        # First differences
        diffs = [hist[i] - hist[i - 1] for i in range(1, len(hist))]

        # Oscillation score: fraction of significant sign flips
        def _sgn(x: float) -> int:
            if abs(x) < OSC_DELTA:
                return 0
            return 1 if x > 0 else -1

        flips = 0
        for i in range(1, len(diffs)):
            s0, s1 = _sgn(diffs[i - 1]), _sgn(diffs[i])
            if s0 != 0 and s1 != 0 and s0 != s1:
                flips += 1
        osc = min(1.0, flips / max(1, len(diffs) - 1))

        # Variance score (normalized)
        mean = sum(hist) / len(hist)
        variance = sum((x - mean) ** 2 for x in hist) / len(hist)
        sigma = math.sqrt(variance)
        var_score = min(1.0, sigma / max(1e-9, SIGMA_MAX))

        # Change point score: proportion of large jumps
        cp_count = sum(1 for d in diffs if abs(d) > CP_DELTA)
        cp = min(1.0, cp_count / max(1, len(diffs)))

        # Softmax weights to emphasize dominant dimension
        e_osc = math.exp(osc)
        e_var = math.exp(var_score)
        e_cp = math.exp(cp)
        z = e_osc + e_var + e_cp
        a = e_osc / z
        b = e_var / z
        c = e_cp / z

        anomaly = a * osc + b * var_score + c * cp
        self.anomaly_index = max(0.0, min(1.0, anomaly))

    # ---- Execution ----------------------------------------------------------

    def simulate_execution(
        self,
        task: TaskSpec,
        action: str,
        base_transmission: float,
        base_execution: float,
        rng,
    ) -> TaskOutcome:
        """
        Execute the task respecting Zero-Trust principles.

        Continuous verification: every request re-evaluates current trust and anomaly.
        Least privilege: partial/test actions throttle workload automatically.
        Assume breach: malicious nodes can be quarantined and flagged for rerouting.
        """
        # Apply action modifiers (least privilege enforcement).
        workload_multiplier = 1.0
        monitoring_flag = False
        if action == "test_task_logging":
            workload_multiplier = 0.25
        elif action == "partial_assignment":
            workload_multiplier = 0.5
        elif action == "full_assignment_monitoring":
            monitoring_flag = True
        elif action == "quarantine":
            self.quarantine = True
            return TaskOutcome(
                task_id=task.task_id,
                dst=self.name,
                assigned_action=action,
                success=False,
                latency=0.0,
                transmission_time=0.0,
                execution_time=0.0,
                reward=-0.3,
                notes={"quarantine": 1.0},
            )

        transmission_time = base_transmission
        execution_time = base_execution * workload_multiplier

        trust_delta = 0.02  # optimistic prior
        notes: Dict[str, float] = {"workload_multiplier": workload_multiplier}
        if monitoring_flag:
            self.monitored = True
            notes["monitoring"] = 1.0

        # Inject malicious behaviour if applicable post least-privilege scaling.
        attacker_notes: Dict[str, float] = {}
        if self.attack_profile:
            logic = MaliciousLogic(self.attack_profile, rng)
            transmission_time, execution_time, trust_delta, attacker_notes = logic.manipulate(
                transmission_time,
                execution_time,
                trust_delta,
            )

        notes.update(attacker_notes)

        # Compute success/failure after modifications using continuous verification.
        total_latency = transmission_time + execution_time
        slowdown_factor = 1.15 if action == "test_task_logging" else 1.05
        deadline_ok = total_latency <= task.deadline * slowdown_factor
        overload_penalty = max(0.0, (execution_time / max(1.0, task.deadline)) - 0.25)

        baseline = 0.2 if not self.is_malicious else 0.05
        success_probability = max(0.05, min(0.98, baseline + self.compute_final_trust() - overload_penalty + trust_delta))
        success = rng.random() < success_probability and deadline_ok

        # Update trust buffers.
        self.running_load = min(1.5, self.running_load * 0.5 + execution_time / max(1.0, task.deadline))
        self.action_history.append(action)
        self.latency_history.append(total_latency)

        if success:
            self.success_count += 1
            trust_increment = min(0.18, 0.06 + trust_delta)
            if self.is_malicious:
                trust_increment *= 0.5
                notes["malicious_success"] = 1.0
            updated_trust = min(1.0, self.trust_history[-1] + trust_increment)
            reward = 0.9 - 0.15 * overload_penalty
            if self.is_malicious:
                reward -= 0.25
        else:
            self.failure_count += 1
            penalty = 1.0 + overload_penalty
            trust_decrement = min(0.4, 0.1 + abs(trust_delta))
            if self.is_malicious:
                penalty *= 1.5
                trust_decrement *= 1.5
                notes["malicious_penalty"] = 1.0
            reward = -penalty
            updated_trust = max(0.0, self.trust_history[-1] - trust_decrement)
            if self.is_malicious:
                updated_trust = max(0.0, updated_trust - 0.05)

        self.trust_history.append(updated_trust)
        self.update_anomaly(updated_trust)

        if not self.is_malicious and self.trust_history[-1] < 0.3:
            self.trust_history[-1] = 0.3
            updated_trust = 0.3

        # Additional Zero-Trust enforcement: high anomaly triggers quarantine suggestion.
        if self.anomaly_index > 0.55 and not self.quarantine:
            notes["auto_quarantine_suggested"] = 1.0

        return TaskOutcome(
            task_id=task.task_id,
            dst=self.name,
            assigned_action=action,
            success=success,
            latency=total_latency,
            transmission_time=transmission_time,
            execution_time=execution_time,
            reward=reward,
            notes=notes,
        )

    # ---- Feature extraction -------------------------------------------------

    def feature_vector(self, graph) -> Dict[str, float]:
        """
        Compute graph-aware features for the RL policy.
        """
        centrality = graph.degree[self.name] / max(1, len(graph) - 1)
        clustering = 0.0
        try:
            clustering = graph.clustering(self.name)
        except Exception:
            # networkx clustering requires undirected; ignore quietly
            clustering = 0.0

        return {
            "final_trust": self.compute_final_trust(),
            "anomaly": self.anomaly_index,
            "load": min(1.5, self.running_load),
            "centrality": centrality,
            "clustering": clustering,
            "quarantine": 1.0 if self.quarantine else 0.0,
            "success_rate": self.performance_trust,
        }


__all__ = ["ZTANode"]
