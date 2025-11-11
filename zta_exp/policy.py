"""
Graph-aware epsilon-greedy reinforcement learning policy.
"""

from __future__ import annotations

import math
import random
from typing import Dict, List, Tuple

import numpy as np
import networkx as nx

from .assignment_matrix import decide_action, action_priority
from .node import ZTANode


FEATURE_KEYS = [
    "final_trust",
    "anomaly",
    "load",
    "success_rate",
    "centrality",
    "clustering",
    "degree",
    "rolling_latency",
    "rolling_failure_rate",
    "neighbor_trust",
    "neighbor_anomaly",
    "neighbor_load",
]


class GNNRLPolicy:
    """
    Lightweight policy inspired by GNNs. Instead of relying on deep learning
    frameworks, we approximate message passing by aggregating neighbour features
    explicitly and learning linear weights through TD(0).
    """

    def __init__(
        self,
        rng: random.Random,
        epsilon: float = 0.2,
        epsilon_min: float = 0.02,
        epsilon_decay: float = 0.99,
        alpha: float = 0.05,
        gamma: float = 0.92,
    ) -> None:
        self.rng = rng
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.alpha = alpha
        self.gamma = gamma

        self.weights = np.zeros(len(FEATURE_KEYS))
        # Encourage initial exploration by biasing towards trust-oriented nodes.
        self.weights[FEATURE_KEYS.index("final_trust")] = 0.6
        self.weights[FEATURE_KEYS.index("anomaly")] = -0.3
        self.weights[FEATURE_KEYS.index("neighbor_trust")] = 0.55
        self.bias = 0.0

        self.history: Dict[str, List[float]] = {"epsilon": [], "reward": []}

    # ------------------------------------------------------------------

    def _neighbor_aggregates(self, graph: nx.Graph, node_name: str, features: Dict[str, float]) -> Dict[str, float]:
        neighbours = list(graph.neighbors(node_name))
        if not neighbours:
            return {"neighbor_trust": features["final_trust"], "neighbor_anomaly": features["anomaly"], "neighbor_load": features["load"]}

        trust_vals, anomaly_vals, load_vals = [], [], []
        for nbr in neighbours:
            data = graph.nodes[nbr].get("features_cache")
            if not data:
                continue
            trust_vals.append(data["final_trust"])
            anomaly_vals.append(data["anomaly"])
            load_vals.append(data["load"])

        if not trust_vals:
            return {"neighbor_trust": features["final_trust"], "neighbor_anomaly": features["anomaly"], "neighbor_load": features["load"]}

        return {
            "neighbor_trust": sum(trust_vals) / len(trust_vals),
            "neighbor_anomaly": sum(anomaly_vals) / len(anomaly_vals),
            "neighbor_load": sum(load_vals) / len(load_vals),
        }

    def _compose_feature_vector(self, base: Dict[str, float], neighbour: Dict[str, float]) -> np.ndarray:
        vec = np.zeros(len(FEATURE_KEYS), dtype=float)
        for idx, key in enumerate(FEATURE_KEYS):
            if key in base:
                vec[idx] = base[key]
            elif key in neighbour:
                vec[idx] = neighbour[key]
        return vec

    def _score(self, features: np.ndarray) -> float:
        return float(np.dot(self.weights, features) + self.bias)

    def select_node_and_action(
        self,
        graph: nx.Graph,
        nodes: Dict[str, ZTANode],
        system_state: Dict[str, str],
    ) -> Tuple[ZTANode, str, np.ndarray, Dict[str, float]]:
        """
        Decide which node to use and the Zero-Trust-compliant action.
        Returns the selected node, action, feature vector, and base features.
        """
        candidates = [node for node in nodes.values() if not node.quarantine]
        if not candidates:
            candidates = list(nodes.values())

        scored_candidates: List[Tuple[ZTANode, float, np.ndarray, Dict[str, float]]] = []
        for node in candidates:
            feature_vec, base_features = self.feature_vector_for(node, graph)
            score = self._score(feature_vec)
            scored_candidates.append((node, score, feature_vec, base_features))
            graph.nodes[node.name]["features_cache"] = base_features  # re-use for neighbours

        exploratory_choice = self.rng.random() < self.epsilon
        if exploratory_choice:
            node, score, vec, base = self.rng.choice(scored_candidates)
        else:
            node, score, vec, base = max(scored_candidates, key=lambda item: item[1])

        action = decide_action(base, system_state)

        # Penalise risky actions implicitly to encourage safe choices.
        if action == "quarantine":
            node.quarantine = True
        elif action == "partial_assignment":
            vec[FEATURE_KEYS.index("load")] *= 0.8

        # Log epsilon for monitoring.
        self.history["epsilon"].append(self.epsilon)
        return node, action, vec, base

    def update(
        self,
        features: np.ndarray,
        reward: float,
        next_feature_bank: List[np.ndarray],
    ) -> None:
        """
        TD(0) update with linear function approximation.
        """
        if next_feature_bank:
            future_values = [self._score(vec) for vec in next_feature_bank]
            future_estimate = max(future_values)
        else:
            future_estimate = 0.0

        prediction = self._score(features)
        target = reward + self.gamma * future_estimate
        td_error = target - prediction

        self.weights += self.alpha * td_error * features
        self.bias += self.alpha * td_error
        self.history["reward"].append(reward)

        # Epsilon decay with floor.
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

    def snapshot(self) -> Dict[str, float]:
        return {
            "epsilon": self.epsilon,
            "alpha": self.alpha,
            "gamma": self.gamma,
            "weight_norm": float(np.linalg.norm(self.weights)),
        }

    def feature_vector_for(self, node: ZTANode, graph: nx.Graph) -> Tuple[np.ndarray, Dict[str, float]]:
        base_features = node.feature_vector(graph)
        neighbour_features = self._neighbor_aggregates(graph, node.name, base_features)
        return self._compose_feature_vector(base_features, neighbour_features), base_features


__all__ = ["GNNRLPolicy", "FEATURE_KEYS"]
