"""
Visualization utilities for adaptive ZTA simulations.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Iterable

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D

from .environment import SimulationResult
from .dataset_catalog import DATASET_CATALOG


def _ensure_dir(path: os.PathLike) -> Path:
    path_obj = Path(path)
    path_obj.mkdir(parents=True, exist_ok=True)
    return path_obj


def plot_trust_trajectories(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    plt.figure(constrained_layout=True, figsize=(12, 7))

    # Colors: normal = blue, malicious = red
    normal_color = "#4C72B0"
    malicious_color = "#C44E52"

    # Determine malicious nodes using multiple fallbacks so plots stay correct
    # across pipelines and historical summaries.
    malicious_flags = {}
    # 1) Prefer explicit flag from snapshots
    for name, snap in result.node_snapshots.items():
        if "malicious" in snap:
            malicious_flags[name] = bool(snap.get("malicious", 0.0) >= 0.5)
    # 2) If missing, infer from dataset catalog (declared malicious profiles)
    if not malicious_flags or not any(malicious_flags.values()):
        try:
            d = next((d for d in DATASET_CATALOG if d.get("name") == result.dataset_name), None)
            if d:
                mp = d.get("malicious_profiles", {})
                for name in result.node_histories.keys():
                    if name in mp:
                        malicious_flags[name] = True
        except Exception:
            pass
    # 3) As a last resort, treat nodes that were permanently quarantined as malicious
    if result.attack_events:
        perm = {e["node"] for e in result.attack_events if str(e.get("event", "")).startswith("quarantine_permanent")}
        for name in perm:
            malicious_flags[name] = True

    # Plot each trajectory with appropriate color
    final_trust_by_node = {name: snap.get("final_trust") for name, snap in result.node_snapshots.items()}

    for node, history in result.node_histories.items():
        ys = history.get("final_trust") or history.get("trust", [])
        if not ys:
            continue
        is_malicious = malicious_flags.get(node, False)
        color = malicious_color if is_malicious else normal_color
        lw = 1.8 if is_malicious else 1.1
        plt.plot(ys, color=color, linewidth=lw)

        # Overlay the summary final_trust as a dot to align with summary.json
        ft = final_trust_by_node.get(node)
        if isinstance(ft, (int, float)):
            x = len(ys) - 1 if ys else 0
            plt.scatter([x], [ft], color=color, s=22, zorder=5)

        # Label malicious nodes at the last point using the summary final_trust if available
        if is_malicious:
            x = len(ys) - 1
            y = float(ft) if isinstance(ft, (int, float)) else (ys[-1] if ys else 0.0)
            plt.text(
                x + 1,
                y,
                node,
                color=malicious_color,
                fontsize=9,
                va="center",
            )

    plt.title(f"Trust Trajectories — {result.dataset_name}")
    plt.xlabel("Observation")
    plt.ylabel("Trust Score")
    plt.ylim(0, 1.05)

    # Category legend only (avoid a huge per-node legend)
    handles = [
        Line2D([0], [0], color=normal_color, lw=2, label="Normal nodes"),
        Line2D([0], [0], color=malicious_color, lw=2, label="Malicious nodes"),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#444', markeredgecolor='#444', markersize=5, label='Final trust (summary)'),
    ]
    plt.legend(handles=handles, loc="upper left", bbox_to_anchor=(1.02, 1), borderaxespad=0.0, fontsize=9)

    path = output_dir / f"{result.dataset_name}_trust_trajectories.png"
    plt.tight_layout(rect=[0, 0, 0.8, 1])
    plt.savefig(path, dpi=220, bbox_inches="tight", pad_inches=0.2)
    plt.close()
    return path


def plot_action_distribution(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    action_counter = Counter(outcome.assigned_action for outcome in result.task_outcomes)
    labels = list(action_counter.keys())
    counts = [action_counter[label] for label in labels]

    plt.figure(constrained_layout=True, figsize=(10, 6))
    plt.bar(labels, counts, color="#4C72B0")
    plt.title(f"Action Distribution — {result.dataset_name}")
    plt.ylabel("Count")
    plt.xticks(rotation=20)
    path = output_dir / f"{result.dataset_name}_action_distribution.png"
    plt.tight_layout(rect=[0, 0, 1, 1])
    plt.savefig(path, dpi=220, bbox_inches="tight", pad_inches=0.2)
    plt.close()
    return path


def plot_reward_curve(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    rewards = result.policy_history.get("reward", [])
    rolling = np.convolve(rewards, np.ones(20) / 20, mode="same") if rewards else []

    plt.figure(constrained_layout=True, figsize=(11, 6))
    plt.plot(rewards, label="Reward")
    if len(rolling):
        plt.plot(rolling, label="Rolling Mean (20)", linestyle="--")
    plt.title(f"Policy Reward Curve — {result.dataset_name}")
    plt.xlabel("Task Index")
    plt.ylabel("Reward")
    plt.legend(loc="upper left", bbox_to_anchor=(1.02, 1), borderaxespad=0.0, fontsize=9)
    path = output_dir / f"{result.dataset_name}_reward_curve.png"
    plt.tight_layout(rect=[0, 0, 0.82, 1])
    plt.savefig(path, dpi=220, bbox_inches="tight", pad_inches=0.2)
    plt.close()
    return path


def plot_malicious_activity(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    plt.figure(figsize=(9, 5))
    events = result.attack_events
    if events:
        task_ids = [event["task_id"] for event in events]
        anomalies = [event.get("anomaly", 0.0) for event in events]
        colors = ["#C44E52" if event["event"].startswith("quarantine") else "#8172B2" for event in events]
        labels = [event["node"] for event in events]
        plt.scatter(task_ids, anomalies, c=colors)
        for task_id, anomaly, label in zip(task_ids, anomalies, labels):
            plt.annotate(label, (task_id, anomaly), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=8)
    plt.title(f"Malicious Activity Indicators — {result.dataset_name}")
    plt.xlabel("Task ID")
    plt.ylabel("Anomaly at Event")
    plt.ylim(0, 1.05)
    path = output_dir / f"{result.dataset_name}_malicious_activity.png"
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()
    return path


def plot_load_balance(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    nodes = list(result.node_snapshots.keys())
    success_rates = [result.node_snapshots[name]["success_rate"] for name in nodes]
    trust_scores = [result.node_snapshots[name]["final_trust"] for name in nodes]

    x = np.arange(len(nodes))
    width = 0.35

    plt.figure(constrained_layout=True, figsize=(12, 6))
    plt.bar(x - width / 2, success_rates, width, label="Success Rate")
    plt.bar(x + width / 2, trust_scores, width, label="Final Trust")
    plt.xticks(x, nodes, rotation=25)
    plt.ylim(0, 1.05)
    plt.title(f"Load & Trust Summary — {result.dataset_name}")
    plt.legend(loc="upper left", bbox_to_anchor=(1.02, 1), borderaxespad=0.0, fontsize=9)
    path = output_dir / f"{result.dataset_name}_load_trust.png"
    plt.tight_layout(rect=[0, 0, 0.82, 1])
    plt.savefig(path, dpi=220, bbox_inches="tight", pad_inches=0.2)
    plt.close()
    return path


def plot_latency_histogram(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    latencies = [outcome.latency for outcome in result.task_outcomes if outcome.latency > 0]

    plt.figure(constrained_layout=True, figsize=(10.5, 6))
    plt.hist(latencies, bins=30, color="#55A868", alpha=0.8)
    plt.title(f"End-to-End Latency Distribution — {result.dataset_name}")
    plt.xlabel("Latency (sim units)")
    plt.ylabel("Frequency")
    path = output_dir / f"{result.dataset_name}_latency_histogram.png"
    plt.tight_layout(rect=[0, 0, 1, 1])
    plt.savefig(path, dpi=220, bbox_inches="tight", pad_inches=0.2)
    plt.close()
    return path


def generate_all_plots(result: SimulationResult, output_dir: os.PathLike) -> Iterable[Path]:
    """
    Convenience helper to emit every standard visualization.
    """
    yield plot_trust_trajectories(result, output_dir)
    yield plot_action_distribution(result, output_dir)
    yield plot_reward_curve(result, output_dir)
    yield plot_malicious_activity(result, output_dir)
    yield plot_load_balance(result, output_dir)
    yield plot_latency_histogram(result, output_dir)


__all__ = [
    "plot_trust_trajectories",
    "plot_action_distribution",
    "plot_reward_curve",
    "plot_malicious_activity",
    "plot_load_balance",
    "plot_latency_histogram",
    "generate_all_plots",
]
