"""
Pipeline entry-points for running adaptive ZTA simulations and generating artefacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .dataset_catalog import DATASET_CATALOG
from .environment import SimulationResult, ZTASimulation
from .visualization import generate_all_plots


def _dataset_by_name(name: str) -> Dict:
    for dataset in DATASET_CATALOG:
        if dataset["name"] == name:
            return dataset
    raise ValueError(f"Unknown dataset '{name}'. Available: {[d['name'] for d in DATASET_CATALOG]}")


def _save_summary(result: SimulationResult, output_dir: Path) -> Path:
    summary = {
        "dataset_name": result.dataset_name,
        "description": result.description,
        "tasks_processed": len(result.task_outcomes),
        "success_rate": sum(o.success for o in result.task_outcomes) / max(1, len(result.task_outcomes)),
        "avg_latency": sum(o.latency for o in result.task_outcomes) / max(1, len(result.task_outcomes)),
        "node_snapshots": result.node_snapshots,
        "policy_history": {k: v[-10:] for k, v in result.policy_history.items()},
        "attack_events": result.attack_events,
        "detection_metrics": result.metrics,
    }
    path = output_dir / "summary.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    return path


def run_dataset(name: str, output_root: Path | str = "logs/zta_new") -> SimulationResult:
    dataset = _dataset_by_name(name)
    output_dir = Path(output_root) / name
    output_dir.mkdir(parents=True, exist_ok=True)

    simulation = ZTASimulation(dataset)
    result = simulation.run()

    # Persist summary and plots.
    _save_summary(result, output_dir)
    for _ in generate_all_plots(result, output_dir):
        pass
    return result


def run_all_datasets(output_root: Path | str = "logs/zta_new") -> Dict[str, SimulationResult]:
    results = {}
    for dataset in DATASET_CATALOG:
        results[dataset["name"]] = run_dataset(dataset["name"], output_root)
    return results


__all__ = ["run_dataset", "run_all_datasets"]
