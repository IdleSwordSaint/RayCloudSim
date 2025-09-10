from __future__ import annotations

from typing import Dict, Tuple


def normalize_delay(total_delay: float, ddl: float | int) -> float:
    """
    Normalize total delay against a deadline to [0, 1].
    If ddl <= 0, treat as unconstrained and clamp by a heuristic.
    """
    if ddl is None or ddl <= 0:
        # Fallback: clamp with a soft bound
        return max(0.0, min(1.0, total_delay / (1.0 + total_delay)))
    return max(0.0, min(1.0, float(total_delay) / float(ddl)))


def pack_resource_usage(overuse_ratio: float = 0.0) -> Dict[str, float]:
    """Helper to construct a resource usage map consumed by ZTANode metrics."""
    return {"overuse": max(0.0, min(1.0, overuse_ratio))}


def collect_completion_stats(task_logger_entry: Tuple[int, list, Tuple[str, str]]):
    """
    Given Env.logger.task_info entry value, return (trans, wait, exe, src, dst).

    Env.logger.task_info format: (status_code, [trans, wait, exe], (src_name, dst_name)).
    """
    status_code, times, names = task_logger_entry
    trans, wait, exe = times if len(times) == 3 else (0.0, 0.0, 0.0)
    src, dst = names
    return trans, wait, exe, src, dst

