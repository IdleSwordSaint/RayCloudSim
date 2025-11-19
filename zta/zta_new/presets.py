"""
Presets to reproduce specific experimental runs.

Use environment variables to activate:
- ZTA_POLICY_PRESET=full_4
- ZTA_RULES_PRESET=full_4
"""

from __future__ import annotations

from typing import Dict, List


# Policy hyperparameter presets
POLICY_PRESETS: Dict[str, Dict[str, float]] = {
    # Snapshot of defaults used for zta_new_full_4
    "full_4": {
        "epsilon": 0.2,
        "epsilon_min": 0.02,
        "epsilon_decay": 0.99,
        "alpha": 0.05,
        "gamma": 0.92,
    }
}


# ZERO_TRUST_RULES presets (structure mirrors assignment_matrix.ZERO_TRUST_RULES)
RULES_PRESETS: Dict[str, List[Dict]] = {
    "full_4": [
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
}


__all__ = ["POLICY_PRESETS", "RULES_PRESETS"]

