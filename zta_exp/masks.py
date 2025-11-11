"""
Zero-Trust guardrail masks for action feasibility.

Masks enforce strong rules as availability masks over actions; policies must
apply them either to Q-values (DQN) or logits (PPO/Actor) before sampling.
"""

from __future__ import annotations

from typing import Dict, List

import numpy as np


ACTIONS: List[str] = [
    "full_assignment",
    "partial_assignment",
    "test_task_logging",
    "quarantine",
    "full_assignment_monitoring",
]


def build_zt_masks(nodes_features: List[Dict[str, float]], system_state: Dict[str, str]) -> np.ndarray:
    """
    Build a binary mask of shape [N, A] indicating which actions are allowed
    for each node given its features and the global system state.
    """
    N, A = len(nodes_features), len(ACTIONS)
    M = np.ones((N, A), dtype=np.float32)
    for i, f in enumerate(nodes_features):
        anomaly = float(f.get("anomaly", 0.0))
        trust = float(f.get("final_trust", 0.0))
        load = float(f.get("load", 0.0))
        allow: set[str]
        if anomaly >= 0.75:
            allow = {"quarantine", "test_task_logging"}
        elif trust >= 0.75 and anomaly <= 0.35:
            allow = {"full_assignment", "full_assignment_monitoring", "test_task_logging"}
        elif system_state.get("system_load") == "high" and load >= 0.6 and trust >= 0.6:
            allow = {"partial_assignment", "test_task_logging"}
        else:
            allow = set(ACTIONS)
        for a_idx, a in enumerate(ACTIONS):
            if a not in allow:
                M[i, a_idx] = 0.0
    return M


def post_veto(node_features: Dict[str, float], system_state: Dict[str, str], chosen_action: str) -> str:
    """
    Optional final safety check which can hard-veto an unsafe action.
    For now, passes through unchanged.
    """
    return chosen_action


__all__ = ["ACTIONS", "build_zt_masks", "post_veto"]

