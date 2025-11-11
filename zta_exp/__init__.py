"""
Adaptive Zero Trust Architecture (ZTA) package.

This package implements a clean-room rewrite of the ZTA simulation stack with:

- Multi-attack malicious node modelling.
- Epsilon-greedy graph-aware reinforcement learning policy.
- Explicit enforcement of Zero-Trust assignment actions.
- Rich instrumentation for diagnostics and visualization.

The public API exposes the dataset catalog, environment runner, and helpers
for plotting results after simulations complete.
"""

from .dataset_catalog import DATASET_CATALOG
from .pipeline import run_dataset, run_all_datasets
from .visualization import (
    plot_action_distribution,
    plot_reward_curve,
    plot_trust_trajectories,
    plot_malicious_activity,
    plot_load_balance,
    plot_latency_histogram,
)

__all__ = [
    "DATASET_CATALOG",
    "run_dataset",
    "run_all_datasets",
    "plot_action_distribution",
    "plot_reward_curve",
    "plot_trust_trajectories",
    "plot_malicious_activity",
    "plot_load_balance",
    "plot_latency_histogram",
]
