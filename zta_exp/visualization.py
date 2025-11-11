"""
Visualization utilities for adaptive ZTA simulations.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Iterable

import matplotlib.pyplot as plt
import glob
import numpy as np

from .environment import SimulationResult


def _ensure_dir(path: os.PathLike) -> Path:
    path_obj = Path(path)
    path_obj.mkdir(parents=True, exist_ok=True)
    return path_obj


def plot_trust_trajectories(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    plt.figure(figsize=(10, 6))
    for node, history in result.node_histories.items():
        plt.plot(history["trust"], label=node)
    plt.title(f"Trust Trajectories — {result.dataset_name}")
    plt.xlabel("Observation")
    plt.ylabel("Trust Score")
    plt.ylim(0, 1.05)
    plt.legend(loc="best")
    path = output_dir / f"{result.dataset_name}_trust_trajectories.png"
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()
    return path


def plot_action_distribution(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    action_counter = Counter(outcome.assigned_action for outcome in result.task_outcomes)
    labels = list(action_counter.keys())
    counts = [action_counter[label] for label in labels]

    plt.figure(figsize=(8, 5))
    plt.bar(labels, counts, color="#4C72B0")
    plt.title(f"Action Distribution — {result.dataset_name}")
    plt.ylabel("Count")
    plt.xticks(rotation=20)
    path = output_dir / f"{result.dataset_name}_action_distribution.png"
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()
    return path


def plot_reward_curve(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    rewards = result.policy_history.get("reward", [])
    rolling = np.convolve(rewards, np.ones(20) / 20, mode="same") if rewards else []

    plt.figure(figsize=(9, 5))
    plt.plot(rewards, label="Reward")
    if len(rolling):
        plt.plot(rolling, label="Rolling Mean (20)", linestyle="--")
    plt.title(f"Policy Reward Curve — {result.dataset_name}")
    plt.xlabel("Task Index")
    plt.ylabel("Reward")
    plt.legend(loc="best")
    path = output_dir / f"{result.dataset_name}_reward_curve.png"
    plt.tight_layout()
    plt.savefig(path, dpi=200)
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

    plt.figure(figsize=(10, 5))
    plt.bar(x - width / 2, success_rates, width, label="Success Rate")
    plt.bar(x + width / 2, trust_scores, width, label="Final Trust")
    plt.xticks(x, nodes, rotation=25)
    plt.ylim(0, 1.05)
    plt.title(f"Load & Trust Summary — {result.dataset_name}")
    plt.legend(loc="best")
    path = output_dir / f"{result.dataset_name}_load_trust.png"
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()
    return path


def plot_latency_histogram(result: SimulationResult, output_dir: os.PathLike) -> Path:
    output_dir = _ensure_dir(output_dir)
    latencies = [outcome.latency for outcome in result.task_outcomes if outcome.latency > 0]

    plt.figure(figsize=(9, 5))
    plt.hist(latencies, bins=30, color="#55A868", alpha=0.8)
    plt.title(f"End-to-End Latency Distribution — {result.dataset_name}")
    plt.xlabel("Latency (sim units)")
    plt.ylabel("Frequency")
    path = output_dir / f"{result.dataset_name}_latency_histogram.png"
    plt.tight_layout()
    plt.savefig(path, dpi=200)
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


def make_video_from_frames(frame_dir: os.PathLike | str, output_path: os.PathLike | str, fps: int = 5) -> Path:
    """
    Combine PNG frames from a directory into a simple MP4 video.
    """
    try:
        import cv2  # type: ignore
    except Exception:
        # OpenCV not available; skip video generation gracefully
        return Path(output_path)
    frame_dir = Path(frame_dir)
    frames = sorted(glob.glob(str(frame_dir / "*.png")))
    if not frames:
        return Path(output_path)
    img = cv2.imread(frames[0])
    if img is None:
        return Path(output_path)
    h, w, _ = img.shape
    out = cv2.VideoWriter(str(output_path), cv2.VideoWriter_fourcc(*"mp4v"), fps, (w, h))
    for f in frames:
        frame = cv2.imread(f)
        if frame is None:
            continue
        out.write(frame)
    out.release()
    return Path(output_path)


__all__ = [
    "plot_trust_trajectories",
    "plot_action_distribution",
    "plot_reward_curve",
    "plot_malicious_activity",
    "plot_load_balance",
    "plot_latency_histogram",
    "generate_all_plots",
    "make_video_from_frames",
]
