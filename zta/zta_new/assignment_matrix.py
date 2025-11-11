"""
Zero-Trust assignment matrix enforcing the three ZTA principles.
"""

from __future__ import annotations

from typing import Dict, Iterable

# Each rule is evaluated in order; the first match wins. Conditions may inspect
# both node-specific features and global system state.
ZERO_TRUST_RULES = [
    # Identity‑agnostic quarantine: reduce false positives across diverse
    # datasets by requiring stronger evidence.
    {
        "name": "quarantine_severe_risk",
        "action": "quarantine",
        "when": {"final_trust_max": 0.50, "anomaly_min": 0.6},
    },
    {
        "name": "quarantine_extreme_anomaly",
        "action": "quarantine",
        "when": {"anomaly_min": 0.85},
    },
    {
        "name": "test_high_criticality",
        "action": "test_task_logging",
        "when": {"system_threat": "alert", "criticality": "high", "final_trust_min": 0.55, "final_trust_max": 0.8},
    },
    {
        "name": "partial_when_overloaded",
        "action": "partial_assignment",
        "when": {"system_load": "high", "load_min": 0.6, "final_trust_min": 0.6},
    },
    {
        "name": "monitoring_medium_anomaly",
        "action": "full_assignment_monitoring",
        "when": {"anomaly_min": 0.4, "anomaly_max": 0.8, "final_trust_min": 0.65},
    },
    {
        "name": "full_assignment_stable",
        "action": "full_assignment",
        "when": {"final_trust_min": 0.75, "anomaly_max": 0.35},
    },
]

DEFAULT_ACTION = "test_task_logging"


def _check_range(value: float, min_key: str, max_key: str, rules: Dict) -> bool:
    lower = rules.get(min_key, float("-inf"))
    upper = rules.get(max_key, float("inf"))
    return lower <= value <= upper


def decide_action(node_features: Dict[str, float], system_state: Dict[str, str]) -> str:
    """
    Returns the first rule action that matches the node features and system state.
    This function encapsulates Zero-Trust policy enforcement used by the RL agent.
    """
    for rule in ZERO_TRUST_RULES:
        cond = rule["when"]
        # Evaluate numeric ranges.
        if "final_trust_min" in cond or "final_trust_max" in cond:
            if not _check_range(node_features.get("final_trust", 0.0), "final_trust_min", "final_trust_max", cond):
                continue
        if "anomaly_min" in cond or "anomaly_max" in cond:
            if not _check_range(node_features.get("anomaly", 0.0), "anomaly_min", "anomaly_max", cond):
                continue
        if "load_min" in cond or "load_max" in cond:
            if not _check_range(node_features.get("load", 0.0), "load_min", "load_max", cond):
                continue
        if "quarantine" in cond:
            if node_features.get("quarantine", 0.0) < cond["quarantine"]:
                continue

        # Evaluate categorical matches.
        if "system_load" in cond and system_state.get("system_load") != cond["system_load"]:
            continue
        if "system_threat" in cond and system_state.get("threat_level") != cond["system_threat"]:
            continue
        if "criticality" in cond and system_state.get("task_criticality") != cond["criticality"]:
            continue

        return rule["action"]

    return DEFAULT_ACTION


def action_priority(actions: Iterable[str]) -> Dict[str, int]:
    """
    Returns a priority mapping for tie-breaking: lower number = higher priority.
    """
    priority_list = ["quarantine", "test_task_logging", "partial_assignment", "full_assignment_monitoring", "full_assignment"]
    return {action: idx for idx, action in enumerate(priority_list) if action in actions}


__all__ = ["ZERO_TRUST_RULES", "decide_action", "action_priority", "DEFAULT_ACTION"]
