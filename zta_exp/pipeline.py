"""
Pipeline entry-points for running adaptive ZTA simulations and generating artefacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .dataset_catalog import DATASET_CATALOG
from .environment import SimulationResult, ZTASimulation
from .visualization import generate_all_plots, make_video_from_frames
from .trainer import train_and_eval


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
    # Auto-generate a simple video from produced frames
    video_path = output_dir / "simulation_video.mp4"
    make_video_from_frames(output_dir, video_path, fps=5)
    return result


def run_all_datasets(output_root: Path | str = "logs/zta_new") -> Dict[str, SimulationResult]:
    results = {}
    for dataset in DATASET_CATALOG:
        results[dataset["name"]] = run_dataset(dataset["name"], output_root)
    return results


def run_eval_modes(
    output_root: Path | str = "logs/zta_new",
    num_episodes: int = 1,
    batch_size: int = 64,
) -> Dict[str, Dict[str, str]]:
    """
    Run the three evaluation modes: rule-only, pure GNN-RL, and hybrid (mask+veto)
    using the transfer split (train on {Milan, 25N50E}, test on {50N50E, Pakistan}).
    Produces plots and a video per dataset and writes metrics.json per mode.
    Returns mapping of mode → {dataset → output_dir}.
    """
    output_map: Dict[str, Dict[str, str]] = {}
    modes = ["rule_only", "pure", "hybrid"]
    for mode in modes:
        eval_results = train_and_eval(
            mode=mode,
            train_datasets=("topo4mec_milan_city", "topo4mec_25n50e"),
            test_datasets=("topo4mec_50n50e", "pakistan_tuple30k"),
            num_episodes=num_episodes,
            batch_size=batch_size,
            output_root=str(output_root),
        )
        mode_map: Dict[str, str] = {}
        for dname, pack in eval_results.items():
            res: SimulationResult = pack["result"]
            metrics = pack["metrics"]
            out_dir = Path(output_root) / f"{dname}_{mode}"
            out_dir.mkdir(parents=True, exist_ok=True)
            # Save summary
            _save_summary(res, out_dir)
            # Save metrics
            metrics_path = out_dir / "metrics.json"
            with metrics_path.open("w", encoding="utf-8") as fh:
                json.dump(metrics, fh, indent=2)
            # Plots and video
            for _ in generate_all_plots(res, out_dir):
                pass
            make_video_from_frames(out_dir, out_dir / "simulation_video.mp4", fps=5)
            mode_map[dname] = str(out_dir)
        output_map[mode] = mode_map
    return output_map


__all__ = ["run_dataset", "run_all_datasets"]
