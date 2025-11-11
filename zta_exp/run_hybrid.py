"""
CLI to train and evaluate the Hybrid (GNN-RL + Zero-Trust masks + veto) mode.

Training datasets default to {Milan City, 25N50E}; evaluation to {50N50E, Pakistan Tuple30K}.
Outputs per dataset are written to logs/zta_new/<dataset>_hybrid/:
- summary.json, metrics.json, standard plots (*.png), and simulation_video.mp4 (if OpenCV installed)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any, Sequence

from .dataset_catalog import dataset_names
from .trainer import train_and_eval
from .visualization import generate_all_plots, make_video_from_frames


def _save_summary_like_pipeline(result, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train + evaluate Hybrid ZTA GNN-RL (mask + veto)")
    parser.add_argument("--episodes", type=int, default=1, help="Training episodes per train dataset (0 = no training)")
    parser.add_argument("--batch-size", type=int, default=128, help="Replay batch size for DQN updates")
    parser.add_argument(
        "--train",
        nargs="+",
        default=["topo4mec_milan_city", "topo4mec_25n50e"],
        help="Training dataset names",
    )
    parser.add_argument(
        "--test",
        nargs="+",
        default=["topo4mec_50n50e", "pakistan_tuple30k"],
        help="Evaluation dataset names",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("logs/zta_hybrid"),
        help="Root output directory (defaults to logs/zta_hybrid)",
    )
    parser.add_argument(
        "--no-video",
        action="store_true",
        help="Skip MP4 video generation (plots are still produced)",
    )
    return parser.parse_args()


def _validate_names(names: Sequence[str]) -> None:
    valid = set(dataset_names())
    unknown = [n for n in names if n not in valid]
    if unknown:
        raise SystemExit(f"Unknown dataset(s): {unknown}. Valid: {sorted(valid)}")


def main() -> None:
    args = _parse_args()
    _validate_names(args.train)
    _validate_names(args.test)

    print(f"[Hybrid] training on {args.train}, evaluating on {args.test}; episodes={args.episodes}, batch={args.batch_size}")
    results: Dict[str, Dict[str, Any]] = train_and_eval(
        mode="hybrid",
        num_episodes=args.episodes,
        batch_size=args.batch_size,
        train_datasets=tuple(args.train),
        test_datasets=tuple(args.test),
        output_root=str(args.output_dir),
    )

    out_map: Dict[str, str] = {}
    for dname, pack in results.items():
        res = pack["result"]
        metrics = pack["metrics"]
        out_dir = args.output_dir / f"{dname}_hybrid"
        _save_summary_like_pipeline(res, out_dir)
        with (out_dir / "metrics.json").open("w", encoding="utf-8") as fh:
            json.dump(metrics, fh, indent=2)
        for _ in generate_all_plots(res, out_dir):
            pass
        if not args.no_video:
            make_video_from_frames(out_dir, out_dir / "simulation_video.mp4", fps=5)
        out_map[dname] = str(out_dir)

    print("[Hybrid] outputs:")
    for d, p in out_map.items():
        print(f" - {d}: {p}")


if __name__ == "__main__":
    main()
