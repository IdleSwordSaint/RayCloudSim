"""
Task abstractions for the adaptive ZTA environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class TaskSpec:
    """Immutable specification for a synthetic task."""

    task_id: int
    arrival_time: float
    size_mb: float
    cycles_per_bit: float
    deadline: float
    src: str
    criticality: str
    sensitivity: str
    trans_bit_rate: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "arrival_time": self.arrival_time,
            "size_mb": self.size_mb,
            "cycles_per_bit": self.cycles_per_bit,
            "deadline": self.deadline,
            "src": self.src,
            "criticality": self.criticality,
            "sensitivity": self.sensitivity,
            "trans_bit_rate": self.trans_bit_rate,
            "metadata": self.metadata,
        }


@dataclass
class TaskOutcome:
    """Metrics captured after a task completes or fails."""

    task_id: int
    dst: str
    assigned_action: str
    success: bool
    latency: float
    transmission_time: float
    execution_time: float
    reward: float
    notes: Dict[str, float] = field(default_factory=dict)


__all__ = ["TaskSpec", "TaskOutcome"]
