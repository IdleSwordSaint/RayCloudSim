"""
Malicious behaviour models used by the ZTA environment.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class AttackProfile:
    node_name: str
    attack_type: str
    intensity: float  # 0–1, higher means more aggressive

    def as_dict(self) -> Dict:
        return {
            "node_name": self.node_name,
            "attack_type": self.attack_type,
            "intensity": self.intensity,
        }


class MaliciousLogic:
    """
    Implements coarse-grained malicious behaviours. The logic is intentionally
    stochastic so that repeated simulations on the same dataset remain useful.
    """

    def __init__(self, profile: AttackProfile, rng: random.Random):
        self.profile = profile
        self.rng = rng

    def manipulate(
        self,
        base_transmission: float,
        base_execution: float,
        trust_delta: float,
    ) -> Tuple[float, float, float, Dict[str, float]]:
        """
        Return modified (transmission_time, execution_time, trust_delta, notes).
        """
        attack = self.profile.attack_type
        intensity = max(0.0, min(1.0, self.profile.intensity))
        notes: Dict[str, float] = {"attack_intensity": intensity}

        if attack == "drop_packets":
            # Increase transmission delay and, with probability, drop the job.
            delay_multiplier = 1 + 0.6 * intensity
            drop_probability = 0.2 + 0.6 * intensity
            notes["drop_probability"] = drop_probability
            if self.rng.random() < drop_probability:
                # Severe penalty: treat as failure (env will catch via success flag).
                trust_delta -= 0.5 * intensity
                notes["forced_failure"] = 1.0
                return base_transmission * delay_multiplier, base_execution, trust_delta, notes
            trust_delta -= 0.1 * intensity
            return base_transmission * delay_multiplier, base_execution, trust_delta, notes

        if attack == "data_poison":
            # Keep timings similar but erode trust and introduce slight jitter.
            jitter = 1 + self.rng.uniform(-0.05, 0.15) * intensity
            tamper_bias = 0.15 + 0.55 * intensity
            notes["tamper_bias"] = tamper_bias
            trust_delta -= tamper_bias
            return base_transmission * jitter, base_execution * jitter, trust_delta, notes

        if attack == "resource_hog":
            # Inflate execution time and reduce effective capacity.
            hog_multiplier = 1.0 + 1.0 * intensity + self.rng.uniform(0.0, 0.25) * intensity
            trust_delta -= 0.25 * intensity
            notes["hog_multiplier"] = hog_multiplier
            return base_transmission, base_execution * hog_multiplier, trust_delta, notes

        # Unknown attack: do nothing to avoid hiding misconfiguration.
        notes["unsupported_attack"] = 1.0
        return base_transmission, base_execution, trust_delta, notes


__all__ = ["AttackProfile", "MaliciousLogic"]
