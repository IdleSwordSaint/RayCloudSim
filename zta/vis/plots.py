import os
from typing import Dict

import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import networkx as nx

from ..zta_node import ZTANode


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def plot_action_counts(action_counts: Dict[str, int], save_path: str) -> None:
    if not action_counts:
        return
    labels = list(action_counts.keys())
    values = [action_counts[k] for k in labels]

    plt.figure(figsize=(8, 4))
    plt.title("Policy Action Counts")
    plt.bar(labels, values, color="#82B0D2")
    plt.ylabel("count")
    plt.xticks(rotation=20)
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def plot_node_metrics(nodes: Dict[str, ZTANode], save_path: str) -> None:
    if not nodes:
        return
    names = list(nodes.keys())
    # Use current anomaly, and compute fused without mutating sliding window
    fused = [nodes[n].compute_fused_trust() for n in names]
    anomaly = [getattr(nodes[n], "anomaly_index", 0.0) for n in names]
    final_trust = [f / (1.0 + a) for f, a in zip(fused, anomaly)]

    x = range(len(names))
    width = 0.35

    plt.figure(figsize=(10, 5))
    plt.title("Node Trust vs. Anomaly")
    plt.bar([i - width / 2 for i in x], final_trust, width=width, label="final_trust", color="#8ECFC9")
    plt.bar([i + width / 2 for i in x], anomaly, width=width, label="anomaly", color="#FA7F6F")
    plt.xticks(list(x), names, rotation=20)
    plt.ylim(0, 1.05)
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def plot_topology_trust(scenario, save_path: str) -> None:
    # Color nodes by final trust estimate (fused/(1+anomaly))
    graph = scenario.infrastructure.graph
    node_data: Dict[str, ZTANode] = nx.get_node_attributes(graph, "data")  # type: ignore
    names = list(node_data.keys())
    fused = [node_data[n].compute_fused_trust() for n in names]
    anomaly = [getattr(node_data[n], "anomaly_index", 0.0) for n in names]
    final_trust = [max(0.0, min(1.0, f / (1.0 + a))) for f, a in zip(fused, anomaly)]

    pos = nx.get_node_attributes(graph, "pos")
    if not pos:
        # Build pos from Location if present
        pos = {}
        for n, node in node_data.items():
            try:
                if node.location is not None:
                    pos[n] = (float(node.location.x), float(node.location.y))
            except Exception:
                pass
        if not pos:
            pos = nx.spring_layout(graph, seed=0)

    cmap = mcolors.LinearSegmentedColormap.from_list(
        "trust_cmap",
        [(0.0, "#FA7F6F"), (0.5, "#FFBE7A"), (1.0, "#8ECFC9")],
    )

    plt.figure(figsize=(8, 5))
    plt.title("Topology Colored by Final Trust")
    nodes = nx.draw_networkx_nodes(
        graph,
        pos=pos,
        node_color=final_trust,
        cmap=cmap,
        vmin=0,
        vmax=1,
        node_size=500,
        linewidths=0.5,
        edgecolors="#333333",
    )
    nx.draw_networkx_labels(graph, pos=pos, font_size=9)
    nx.draw_networkx_edges(graph, pos=pos, arrows=False, edge_color="#BBBBBB", width=1.2)
    cb = plt.colorbar(nodes, pad=0.02, fraction=0.046)
    cb.set_label("final_trust", rotation=90)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def render_zta_summary(env, scenario, save_dir: str) -> Dict[str, str]:
    """Render a small set of PNG plots summarizing the run.

    Returns a dict of plot_name -> file_path for convenience.
    """
    _ensure_dir(save_dir)
    outputs: Dict[str, str] = {}

    # Action counts bar
    p1 = os.path.join(save_dir, "plots_action_counts.png")
    plot_action_counts(getattr(env, "action_counts", {}), p1)
    outputs["action_counts"] = p1

    # Node metrics bar
    p2 = os.path.join(save_dir, "plots_node_metrics.png")
    plot_node_metrics(scenario.get_nodes(), p2)
    outputs["node_metrics"] = p2

    # Topology colored by trust
    p3 = os.path.join(save_dir, "topology_trust.png")
    plot_topology_trust(scenario, p3)
    outputs["topology_trust"] = p3

    return outputs

