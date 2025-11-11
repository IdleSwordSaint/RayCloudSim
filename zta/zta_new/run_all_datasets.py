"""
CLI script to execute all adaptive ZTA datasets and generate visualisations.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .dataset_catalog import dataset_names
from .pipeline import run_all_datasets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run all adaptive ZTA datasets and generate artefacts.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("logs/zta_new"),
        help="Directory where summaries and plots will be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    results = run_all_datasets(args.output_dir)
    print("Completed datasets:")
    for name in dataset_names():
        summary_path = args.output_dir / name / "summary.json"
        plot_dir = args.output_dir / name
        print(f"  - {name}: summary -> {summary_path}, plots in {plot_dir}")
    print(f"Generated {sum(len(res.task_outcomes) for res in results.values())} task simulations across {len(results)} datasets.")


if __name__ == "__main__":
    main()
