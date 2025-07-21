import numpy as np
from typing import Optional, List, Dict
import math
import random
from collections import deque
from sklearn.ensemble import IsolationForest
from core.infrastructure import Node,Location

class ZTANode(Node):
    """
    Zero Trust Architecture (ZTA) Node for fog simulation.
    Inherits from core.infrastructure.Node and adds ZTA trust and anomaly metrics.
    """
    def __init__(self, node_id: int, name: str, max_cpu_freq: float, max_buffer_size: int = 0,
                 location: Optional[object] = None, idle_energy_coef: float = 0.0, exe_energy_coef: float = 0.0,
                 window_size: int = 5):
        super().__init__(node_id, name, max_cpu_freq, max_buffer_size, location, idle_energy_coef, exe_energy_coef)
        # ZTA trust-related attributes
        self.task_history: List[dict] = []  # Each dict: {task_id, success, delay, resource_usage, criticality, timestamp}
        self.feedback_scores: Dict[str, List[float]] = {}  # Feedback received from other nodes
        self.trust_sliding_window = deque(maxlen=window_size)
        self.anomaly_index: float = 0.0
        self.malicious_type: Optional[int] = None  # For simulating attacks
        self.window_size = window_size  # Store window size for reference

    def add_task_result(self, task_id: str, success: bool, delay: float,
                        resource_usage: dict, criticality: str, timestamp: float):
        """Record the result of a completed task."""
        self.task_history.append({
            'task_id': task_id,
            'success': success,
            'delay': delay,
            'resource_usage': resource_usage,
            'criticality': criticality,
            'timestamp': timestamp
        })

    def add_feedback(self, from_node: str, score: float):
        """Add feedback score received from another node."""
        if from_node not in self.feedback_scores:
            self.feedback_scores[from_node] = []
        self.feedback_scores[from_node].append(score)

    def update_trust_sliding_window(self, fused_trust: float):
        """Append a new trust score to the sliding window."""
        self.trust_sliding_window.append(fused_trust)

    def set_anomaly_index(self, anomaly_index: float):
        """Set the most recent anomaly index value."""
        self.anomaly_index = anomaly_index

    def set_malicious_type(self, mal_type: int):
        """Set the type of malicious behavior for simulation purposes."""
        self.malicious_type = mal_type

    def compute_performance_trust(self) -> float:
        """Compute performance trust as successful tasks / total tasks."""
        total = len(self.task_history)
        if total == 0:
            return 0.0
        success_count = sum(1 for task in self.task_history if task['success'])
        return success_count / total

    def compute_feedback_trust(self, method='iqr') -> float:
        all_scores = [score for scores in self.feedback_scores.values() for score in scores]
        if not all_scores:
            return 0.0

        if method == 'iqr':
            q1, q3 = np.percentile(all_scores, [25, 75])
            iqr = q3 - q1
            filtered = [x for x in all_scores if q1 - 1.5 * iqr <= x <= q3 + 1.5 * iqr]
        elif method == 'isoforest':
            if len(all_scores) < 5:
                filtered = all_scores  # Isolation Forest needs at least a few samples
            else:
                X = np.array(all_scores).reshape(-1, 1)
                clf = IsolationForest(contamination=0.2, random_state=42)
                preds = clf.fit_predict(X)
                filtered = [x for x, p in zip(all_scores, preds) if p == 1]
        else:
            filtered = all_scores

        return np.mean(filtered) if filtered else 0.0

    def compute_behavioral_trust(self) -> float:
        """Compute behavioral trust as 1 - (normalized delay + overuse penalty)."""
        if not self.task_history:
            return 1.0
        delays = [task['delay'] for task in self.task_history]
        overuse = [task['resource_usage'].get('overuse', 0.0) for task in self.task_history]
        norm_delay = np.clip(np.mean(delays), 0, 1) if delays else 0.0
        norm_overuse = np.clip(np.mean(overuse), 0, 1) if overuse else 0.0
        return 1.0 - (norm_delay + norm_overuse)

    def compute_fused_trust(self) -> float:
        """Compute fused trust using geometric and arithmetic aggregation."""
        tperf = self.compute_performance_trust()
        tfb = self.compute_feedback_trust()
        tbeh = self.compute_behavioral_trust()
        denom = (tperf + tfb + tbeh) / 3 if (tperf + tfb + tbeh) else 1.0
        numer = np.sqrt(tperf * tfb * tbeh) if tperf * tfb * tbeh > 0 else 0.0
        return numer / denom

    def compute_anomaly_metrics(self, sigma_max: float = 0.25, cmax: int = 3) -> tuple:
        """
        Compute oscillation, variance, and change point scores from the trust sliding window.
        Args:
            sigma_max (float): Maximum expected standard deviation for normalization (default 0.25).
            cmax (int): Maximum number of change points for normalization (default 3).
        Returns:
            tuple: (oscillation_score, variance_score, change_point_score)
        """
        window = self.get_trust_window()
        k = len(window)
        if k < 2:
            return 0.0, 0.0, 0.0
        # Oscillation: number of trust flips / (k-1)
        flips = sum((window[i] - window[i-1]) * (window[i+1] - window[i]) < 0 for i in range(1, k-1))
        osc = flips / (k - 1)
        # Variance: std / sigma_max
        var = float(np.std(window)) / sigma_max if sigma_max else 0.0
        # Change points: count large jumps / cmax
        change_points = sum(abs(window[i+1] - window[i]) > 0.2 for i in range(k - 1))
        cp = change_points / cmax if cmax else 0.0
        return osc, var, cp

    def compute_anomaly_index(self, sigma_max: float = 0.25, cmax: int = 3) -> float:
        """
        Compute adaptive anomaly index using softmax weighting of oscillation, variance, and change point scores.
        Args:
            sigma_max (float): Maximum expected standard deviation for normalization.
            cmax (int): Maximum number of change points for normalization.
        Returns:
            float: Adaptive anomaly index.
        """
        osc, var, cp = self.compute_anomaly_metrics(sigma_max=sigma_max, cmax=cmax)
        e_osc, e_var, e_cp = np.exp([osc, var, cp])
        Z = e_osc + e_var + e_cp
        alpha, beta, gamma = e_osc / Z, e_var / Z, e_cp / Z
        anomaly_index = alpha * osc + beta * var + gamma * cp
        self.anomaly_index = anomaly_index
        return anomaly_index

    def compute_final_trust(self, sigma_max: float = 0.25, cmax: int = 3) -> float:
        """
        Compute final trust score, penalized by adaptive anomaly index.
        Args:
            sigma_max (float): Maximum expected standard deviation for normalization.
            cmax (int): Maximum number of change points for normalization.
        Returns:
            float: Final trust score.
        """
        tfused = self.compute_fused_trust()
        self.update_trust_sliding_window(tfused)
        anomaly = self.compute_anomaly_index(sigma_max=sigma_max, cmax=cmax)
        t_final = tfused / (1 + anomaly)
        return t_final

    def get_energy_consumption(self) -> float:
        """Return total energy consumption."""
        return self.energy_consumption

    def update_energy_consumption(self, active_time: float, executing: bool):
        """Update energy consumption based on activity."""
        coef = self.exe_energy_coef if executing else self.idle_energy_coef
        self.energy_consumption += coef * active_time

    def get_trust_window(self) -> list:
        """Return the current trust sliding window as a list."""
        return list(self.trust_sliding_window)

    def get_trust_window_mean(self) -> float:
        """Return the mean of the trust sliding window."""
        window = self.get_trust_window()
        return float(np.mean(window)) if window else 0.0

    def get_trust_window_std(self) -> float:
        """Return the standard deviation of the trust sliding window."""
        window = self.get_trust_window()
        return float(np.std(window)) if window else 0.0

    def node_info_str(self) -> str:
        """
        Return a string with all key node info, including trust window, trust metrics, and node attributes.
        """
        info = [
            f"Node ID: {self.node_id}",
            f"Name: {self.name}",
            f"Max CPU Freq: {self.max_cpu_freq}",
            f"Free CPU Freq: {self.free_cpu_freq}",
            f"Location: {self.location}",
            f"Idle Energy Coef: {self.idle_energy_coef}",
            f"Exe Energy Coef: {self.exe_energy_coef}",
            f"Energy Consumption: {self.energy_consumption}",
            f"Malicious Type: {self.malicious_type}",
            f"Trust Sliding Window (size={self.window_size}): {self.get_trust_window()}",
            f"Trust Window Mean: {self.get_trust_window_mean():.4f}",
            f"Trust Window Std: {self.get_trust_window_std():.4f}",
            f"Performance Trust: {self.compute_performance_trust():.4f}",
            f"Feedback Trust: {self.compute_feedback_trust():.4f}",
            f"Behavioral Trust: {self.compute_behavioral_trust():.4f}",
            f"Fused Trust: {self.compute_fused_trust():.4f}",
            f"Anomaly Index: {self.anomaly_index:.4f}",
        ]
        return "\n".join(info)
