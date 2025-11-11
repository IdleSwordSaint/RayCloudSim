"""
Dataset catalog for the adaptive ZTA environment.

The catalog now binds to the official RayCloudSim benchmark datasets:
- Topo4MEC (Milan City, 25N50E, 50N50E, 100N150E)
- Pakistan Telecom (Tuple30K/50K/100K)

For each dataset we derive a manageable sub-topology from the published
configuration files and use the released task CSVs as workload sources.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

# Supported malicious attack types. The environment validates against these.
SUPPORTED_ATTACKS: Sequence[str] = (
    "drop_packets",
    "data_poison",
    "resource_hog",
)


# ---------------------------------------------------------------------------
# Helper utilities


def _load_config(path: str) -> Dict:
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _subset_topology(
    config_path: str,
    selected_nodes: Iterable[str] | None,
    role_overrides: Dict[str, str],
    trust_overrides: Dict[str, float] | None = None,
    default_role: str = "edge",
) -> Tuple[List[Dict], List[Tuple[str, str, Dict[str, float]]]]:
    """
    Extract a lightweight topology subset from the official configuration file.
    """
    trust_overrides = trust_overrides or {}
    config = _load_config(config_path)
    node_lookup = {node["NodeName"]: node for node in config["Nodes"]}
    id_to_name = {node["NodeId"]: node["NodeName"] for node in config["Nodes"]}
    if selected_nodes is None:
        selected_nodes = list(node_lookup.keys())
    else:
        selected_nodes = list(selected_nodes)

    nodes: List[Dict] = []
    trust_defaults = {
        "controller": 0.72,
        "relay": 0.6,
        "edge": 0.58,
        "cloud": 0.68,
    }

    for name in selected_nodes:
        src = node_lookup.get(name)
        if not src:
            raise ValueError(f"Node '{name}' not found in config '{config_path}'.")
        role = role_overrides.get(name, default_role)
        raw_cpu = float(src.get("MaxCpuFreq", 1500))
        cpu = raw_cpu * 8.0  # boost headroom for honest nodes

        raw_buffer = float(src.get("MaxBufferSize", 256))
        mem = max(8.0, raw_buffer / 8.0)

        initial_trust = trust_overrides.get(name, trust_defaults.get(role, 0.6))
        nodes.append(
            {
                "name": name,
                "role": role,
                "cpu": round(cpu, 2),
                "memory": round(mem, 2),
                "initial_trust": round(initial_trust, 2),
            }
        )

    edges: Dict[Tuple[str, str], Dict[str, float]] = {}
    for edge in config["Edges"]:
        src_name = id_to_name.get(edge["SrcNodeID"])
        dst_name = id_to_name.get(edge["DstNodeID"])
        if src_name not in selected_nodes or dst_name not in selected_nodes:
            continue
        key = tuple(sorted((src_name, dst_name)))
        raw_bandwidth = float(edge.get("Bandwidth", 100.0))
        bandwidth = max(1.0, raw_bandwidth) * 1_000_000.0

        raw_latency = edge.get("Latency")
        if raw_latency is None:
            raw_latency = edge.get("Delay")
        raw_latency = float(raw_latency) if raw_latency is not None else 0.0
        if raw_latency <= 0.0:
            if bandwidth >= 800:
                latency = 5.0
            elif bandwidth >= 400:
                latency = 7.0
            elif bandwidth >= 200:
                latency = 10.0
            else:
                latency = 14.0
        else:
            latency = max(1.0, raw_latency)

        entry = edges.setdefault(key, {"bandwidth": bandwidth, "latency": latency})
        entry["bandwidth"] = max(entry["bandwidth"], bandwidth)
        entry["latency"] = min(entry["latency"], latency)

    links = [(src, dst, attrs) for (src, dst), attrs in edges.items()]
    return nodes, links


# ---------------------------------------------------------------------------
# Pre-computed topology snippets


_MILAN_SELECTED = None
_MILAN_ROLES = {
    "n0": "controller",
    "n1": "edge",
    "n3": "relay",
    "n5": "edge",
    "n8": "edge",
    "n12": "relay",
    "n13": "edge",
    "n15": "edge",
    "n18": "edge",
    "n22": "relay",
    "n23": "relay",
}
_MILAN_TRUST = {"n22": 0.55}
MILAN_NODES, MILAN_LINKS = _subset_topology(
    "eval/benchmarks/Topo4MEC/data/MilanCityCenter/config.json",
    _MILAN_SELECTED,
    _MILAN_ROLES,
    trust_overrides=_MILAN_TRUST,
)

_TOPO25_SELECTED = None
_TOPO25_ROLES = {
    "n5": "controller",
    "n9": "edge",
    "n12": "relay",
    "n16": "edge",
    "n18": "edge",
    "n21": "relay",
    "n22": "relay",
    "n24": "edge",
}
TOPO25_NODES, TOPO25_LINKS = _subset_topology(
    "eval/benchmarks/Topo4MEC/data/25N50E/config.json",
    _TOPO25_SELECTED,
    _TOPO25_ROLES,
)

_TOPO50_SELECTED = None
_TOPO50_ROLES = {
    "n2": "controller",
    "n3": "relay",
    "n8": "edge",
    "n11": "edge",
    "n16": "edge",
    "n24": "relay",
    "n35": "relay",
    "n37": "edge",
    "n40": "edge",
    "n47": "relay",
}
TOPO50_NODES, TOPO50_LINKS = _subset_topology(
    "eval/benchmarks/Topo4MEC/data/50N50E/config.json",
    _TOPO50_SELECTED,
    _TOPO50_ROLES,
)

_TOPO100_SELECTED = None
_TOPO100_ROLES = {
    "n50": "controller",
    "n53": "relay",
    "n58": "edge",
    "n64": "edge",
    "n70": "edge",
    "n84": "edge",
    "n22": "relay",
    "n27": "relay",
    "n31": "edge",
    "n33": "relay",
    "n43": "relay",
    "n48": "relay",
    "n49": "edge",
    "n61": "edge",
    "n66": "relay",
    "n67": "edge",
    "n76": "edge",
    "n91": "relay",
}
TOPO100_NODES, TOPO100_LINKS = _subset_topology(
    "eval/benchmarks/Topo4MEC/data/100N150E/config.json",
    _TOPO100_SELECTED,
    _TOPO100_ROLES,
)

_PAKISTAN_SELECTED = ["e0", "f0", "f1", "f2", "f3", "f4", "c0", "c1"]
_PAKISTAN_ROLES = {
    "e0": "edge",
    "f0": "controller",
    "f1": "relay",
    "f2": "relay",
    "f3": "relay",
    "f4": "relay",
    "c0": "cloud",
    "c1": "cloud",
}
_PAKISTAN_TRUST = {"f0": 0.7, "c0": 0.72, "c1": 0.72}
PAKISTAN_NODES, PAKISTAN_LINKS = _subset_topology(
    "eval/benchmarks/Pakistan/data/Tuple30K/config.json",
    _PAKISTAN_SELECTED,
    _PAKISTAN_ROLES,
    trust_overrides=_PAKISTAN_TRUST,
)


# ---------------------------------------------------------------------------
# Dataset catalog


DATASET_CATALOG: List[Dict] = [
    {
        "name": "topo4mec_milan_city",
        "source": "Topo4MEC — Milan City Center graph (Xiang et al., Data in Brief 39, 2021)",
        "description": (
            "Milan City Center MEC deployment with dense street-level nodes. "
            "Ingresses (n0, n1, n5, n13, n15, n18, n22) generate tasks based on the official trainset."
        ),
        "seed": 42,
        "topology": {
            "nodes": MILAN_NODES,
            "links": MILAN_LINKS,
        },
        "malicious_profiles": {
            "n15": {"attack_type": "drop_packets", "intensity": 0.45},
            "n22": {"attack_type": "resource_hog", "intensity": 0.35},
            "n12": {"attack_type": "data_poison", "intensity": 0.7},
        },
        "task_source": {
            "path": "eval/benchmarks/Topo4MEC/data/MilanCityCenter/trainset.csv",
            "time_column": "GenerationTime",
            "size_column": "TaskSize",
            "cycles_column": "CyclesPerBit",
            "deadline_column": "DDL",
            "bitrate_column": "TransBitRate",
            "src_column": "SrcName",
            "criticality_thresholds": [25.0, 55.0],
            "size_sensitivity": [
                {"max": 40.0, "label": "public"},
                {"max": 75.0, "label": "confidential"},
                {"label": "mission"},
            ],
            "size_divisor": 1024.0,
            "size_to_bits": 8192.0,
            "bitrate_multiplier": 1_000_000.0,
        },
    },
    {
        "name": "topo4mec_25n50e",
        "source": "Topo4MEC — 25 nodes / 50 edges synthetic metro graph",
        "description": (
            "Sparse yet wide-area metro topology; ingress subset taken from the official trainset."
        ),
        "seed": 101,
        "topology": {
            "nodes": TOPO25_NODES,
            "links": TOPO25_LINKS,
        },
        "malicious_profiles": {
            "n22": {"attack_type": "data_poison", "intensity": 0.4},
        },
        "task_source": {
            "path": "eval/benchmarks/Topo4MEC/data/25N50E/trainset.csv",
            "time_column": "GenerationTime",
            "size_column": "TaskSize",
            "cycles_column": "CyclesPerBit",
            "deadline_column": "DDL",
            "bitrate_column": "TransBitRate",
            "src_column": "SrcName",
            "criticality_thresholds": [30.0, 60.0],
            "size_sensitivity": [
                {"max": 35.0, "label": "public"},
                {"max": 70.0, "label": "confidential"},
                {"label": "mission"},
            ],
            "size_divisor": 1024.0,
            "size_to_bits": 8192.0,
            "bitrate_multiplier": 1_000_000.0,
        },
    },
    {
        "name": "topo4mec_50n50e",
        "source": "Topo4MEC — 50 nodes / 50 edges sparse backbone",
        "description": (
            "Medium-size backbone; subset of ingress points used for zero-trust scheduling."
        ),
        "seed": 13,
        "topology": {
            "nodes": TOPO50_NODES,
            "links": TOPO50_LINKS,
        },
        "malicious_profiles": {
            "n35": {"attack_type": "resource_hog", "intensity": 0.4},
        },
        "task_source": {
            "path": "eval/benchmarks/Topo4MEC/data/50N50E/trainset.csv",
            "time_column": "GenerationTime",
            "size_column": "TaskSize",
            "cycles_column": "CyclesPerBit",
            "deadline_column": "DDL",
            "bitrate_column": "TransBitRate",
            "src_column": "SrcName",
            "criticality_thresholds": [28.0, 58.0],
            "size_sensitivity": [
                {"max": 38.0, "label": "public"},
                {"max": 80.0, "label": "confidential"},
                {"label": "mission"},
            ],
            "size_divisor": 1024.0,
            "size_to_bits": 8192.0,
            "bitrate_multiplier": 1_000_000.0,
        },
    },
    {
        "name": "topo4mec_100n150e",
        "source": "Topo4MEC — 100 nodes / 150 edges dense macro topology",
        "description": (
            "Dense macro topology; six ingress points retained for tractable zero-trust simulation."
        ),
        "seed": 77,
        "topology": {
            "nodes": TOPO100_NODES,
            "links": TOPO100_LINKS,
        },
        "malicious_profiles": {
            "n53": {"attack_type": "data_poison", "intensity": 0.45},
            "n58": {"attack_type": "resource_hog", "intensity": 0.5},
        },
        "task_source": {
            "path": "eval/benchmarks/Topo4MEC/data/100N150E/trainset.csv",
            "time_column": "GenerationTime",
            "size_column": "TaskSize",
            "cycles_column": "CyclesPerBit",
            "deadline_column": "DDL",
            "bitrate_column": "TransBitRate",
            "src_column": "SrcName",
            "criticality_thresholds": [26.0, 52.0],
            "size_sensitivity": [
                {"max": 32.0, "label": "public"},
                {"max": 68.0, "label": "confidential"},
                {"label": "mission"},
            ],
            "size_divisor": 1024.0,
            "size_to_bits": 8192.0,
            "bitrate_multiplier": 1_000_000.0,
        },
    },
    {
        "name": "pakistan_tuple30k",
        "source": "Pakistan Telecom Network Dataset — Tuple30K slice (Anwar et al.)",
        "description": (
            "Urban Pakistan slice with macro base stations and fog/controller layers. "
            "Tasks sampled from the official Tuple30K trainset."
        ),
        "seed": 5,
        "topology": {
            "nodes": PAKISTAN_NODES,
            "links": PAKISTAN_LINKS,
        },
        "malicious_profiles": {
            "f1": {"attack_type": "data_poison", "intensity": 0.4},
            "f3": {"attack_type": "resource_hog", "intensity": 0.35},
        },
        "task_source": {
            "path": "eval/benchmarks/Pakistan/data/Tuple30K/trainset.csv",
            "time_column": "GenerationTime",
            "size_column": "TaskSize",
            "cycles_column": "CyclesPerBit",
            "deadline_column": "DDL",
            "device_column": "DeviceType",
            "data_type_column": "DataType",
            "allowed_roles_map": {
                "Mobile": ["edge"],
                "Sensor": ["edge"],
                "DumbObjects": ["edge"],
                "Acuator": ["edge"],
                "Nodes": ["relay"],
            },
            "sensitivity_map": {
                "Medical": "mission",
                "Abrupt": "confidential",
                "Multimedia": "confidential",
                "Large": "confidential",
                "Bulk": "public",
                "SmallTextual": "public",
                "LocationBased": "public",
            },
            "criticality_thresholds": [35.0, 70.0],
            "metadata_columns": ["DataType", "DeviceType"],
            "size_divisor": 1024.0,
            "size_to_bits": 8192.0,
            "bitrate_multiplier": 1_000_000.0,
        },
    },
    {
        "name": "pakistan_tuple50k",
        "source": "Pakistan Telecom Network Dataset — Tuple50K slice",
        "description": (
            "Higher-density metropolitan slice with redundant metro controllers."
        ),
        "seed": 11,
        "topology": {
            "nodes": PAKISTAN_NODES,
            "links": PAKISTAN_LINKS,
        },
        "malicious_profiles": {
            "f2": {"attack_type": "drop_packets", "intensity": 0.45},
        },
        "task_source": {
            "path": "eval/benchmarks/Pakistan/data/Tuple50K/trainset.csv",
            "time_column": "GenerationTime",
            "size_column": "TaskSize",
            "cycles_column": "CyclesPerBit",
            "deadline_column": "DDL",
            "device_column": "DeviceType",
            "data_type_column": "DataType",
            "allowed_roles_map": {
                "Mobile": ["edge"],
                "Sensor": ["edge"],
                "DumbObjects": ["edge"],
                "Acuator": ["edge"],
                "Nodes": ["relay", "controller"],
            },
            "sensitivity_map": {
                "Medical": "mission",
                "Abrupt": "confidential",
                "Multimedia": "confidential",
                "Large": "confidential",
                "Bulk": "public",
                "SmallTextual": "public",
                "LocationBased": "public",
            },
            "criticality_thresholds": [32.0, 65.0],
            "metadata_columns": ["DataType", "DeviceType"],
            "size_divisor": 1024.0,
            "size_to_bits": 8192.0,
            "bitrate_multiplier": 1_000_000.0,
        },
    },
    {
        "name": "pakistan_tuple100k",
        "source": "Pakistan Telecom Network Dataset — Tuple100K slice",
        "description": (
            "Nation-scale slice with long-haul links; tasks taken from the official Tuple100K trainset."
        ),
        "seed": 19,
        "topology": {
            "nodes": PAKISTAN_NODES,
            "links": PAKISTAN_LINKS,
        },
        "malicious_profiles": {
            "f4": {"attack_type": "data_poison", "intensity": 0.5},
            "c1": {"attack_type": "resource_hog", "intensity": 0.45},
        },
        "task_source": {
            "path": "eval/benchmarks/Pakistan/data/Tuple100K/trainset.csv",
            "time_column": "GenerationTime",
            "size_column": "TaskSize",
            "cycles_column": "CyclesPerBit",
            "deadline_column": "DDL",
            "device_column": "DeviceType",
            "data_type_column": "DataType",
            "allowed_roles_map": {
                "Mobile": ["edge"],
                "Sensor": ["edge"],
                "DumbObjects": ["edge"],
                "Acuator": ["edge"],
                "Nodes": ["relay", "controller"],
            },
            "sensitivity_map": {
                "Medical": "mission",
                "Abrupt": "confidential",
                "Multimedia": "confidential",
                "Large": "confidential",
                "Bulk": "public",
                "SmallTextual": "public",
                "LocationBased": "public",
            },
            "criticality_thresholds": [30.0, 60.0],
            "metadata_columns": ["DataType", "DeviceType"],
            "size_divisor": 1024.0,
            "size_to_bits": 8192.0,
            "bitrate_multiplier": 1_000_000.0,
        },
    },
]


def dataset_names() -> List[str]:
    """Convenience helper for CLI listings and validation."""
    return [entry["name"] for entry in DATASET_CATALOG]


__all__ = ["DATASET_CATALOG", "SUPPORTED_ATTACKS", "dataset_names"]
