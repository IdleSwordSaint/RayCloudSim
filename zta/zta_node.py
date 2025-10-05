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
                 window_size: int = 5,
                 fused_mode: str = "paper",
                 sigma_max: float = 0.25,
                 cmax: int = 3,
                 cp_threshold: float = 0.2,
                 feedback_baseline: float = 0.5):
        super().__init__(node_id, name, max_cpu_freq, max_buffer_size, location, idle_energy_coef, exe_energy_coef)
        # ZTA trust-related attributes
        self.task_history: List[dict] = []  # Each dict: {task_id, success, delay, resource_usage, criticality, timestamp}
        self.feedback_scores: Dict[str, List[float]] = {}  # Feedback received from other nodes
        self.trust_sliding_window = deque(maxlen=window_size)
        self.anomaly_index: float = 0.0
        self.malicious_type: Optional[int] = None  # For simulating attacks
        self.window_size = window_size  # Store window size for reference
        # Configurable behavior
        self.fused_mode = fused_mode  # "paper" or "robust"
        self.sigma_max = sigma_max
        self.cmax = cmax
        self.cp_threshold = cp_threshold
        self.feedback_baseline = feedback_baseline

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

    def compute_feedback_trust(self, method: str = 'iqr', rater_weights: Optional[Dict[str, float]] = None) -> float:
        """Weighted feedback trust with optional outlier filtering.

        Implements Eq.(2): T_fb = sum_i w_i R_ij / sum_i w_i
        - Filters ratings via IQR or IsolationForest if requested.
        - If rater_weights is None, uses a smart default: weight ∝ sqrt(count_by_rater).
        - Falls back to a neutral baseline (self.feedback_baseline) when no feedback exists.
        """
        all_pairs = [(rater, score) for rater, scores in self.feedback_scores.items() for score in scores]
        if not all_pairs:
            return float(self.feedback_baseline)

        scores_only = [s for _, s in all_pairs]

        # Outlier filtering
        if method == 'iqr':
            q1, q3 = np.percentile(scores_only, [25, 75])
            iqr = q3 - q1
            keep = lambda x: (q1 - 1.5 * iqr) <= x <= (q3 + 1.5 * iqr)
            filtered = [(r, s) for r, s in all_pairs if keep(s)]
        elif method == 'isoforest' and len(scores_only) >= 5:
            X = np.array(scores_only).reshape(-1, 1)
            preds = IsolationForest(contamination=0.2, random_state=42).fit_predict(X)
            filtered = [p for p, pred in zip(all_pairs, preds) if pred == 1]
        else:
            filtered = all_pairs

        if not filtered:
            return 0.0

        # Weights
        if rater_weights:
            acc = 0.0
            wsum = 0.0
            for rater, s in filtered:
                w = float(rater_weights.get(rater, 1.0))
                acc += w * s
                wsum += w
            return acc / wsum if wsum > 0 else float(np.mean([s for _, s in filtered]))
        else:
            # Smart default: weight by sqrt(count per rater) to prefer consistent raters
            counts = {r: len(self.feedback_scores.get(r, [])) for r, _ in filtered}
            acc = 0.0
            wsum = 0.0
            for rater, s in filtered:
                w = math.sqrt(float(counts.get(rater, 1)))
                acc += w * s
                wsum += w
            return acc / wsum if wsum > 0 else float(np.mean([s for _, s in filtered]))

    def compute_behavioral_trust(self) -> float:
        """Compute behavioral trust per Eq.(3): 1 - (NormalizedDelay + OverusePenalty).

        Supports two input conventions per-task:
        - If task['delay'] is absolute and task['resource_usage'].has 'expected_time', we use delay/expected_time.
        - If 'delay' already normalized in [0,1], we use it directly; else use soft normalization d/(1+d).
        - Overuse prefers normalized 'overuse' in [0,1]; otherwise, when 'used' and 'quota' exist, uses max(0, used-quota)/quota.
        """
        if not self.task_history:
            return 1.0

        norm_delays: List[float] = []
        norm_overuses: List[float] = []

        for t in self.task_history:
            d = float(t.get('delay', 0.0))
            ru = t.get('resource_usage', {}) or {}
            # Delay normalization
            if 'expected_time' in ru and ru['expected_time']:
                dnorm = d / max(1e-9, float(ru['expected_time']))
            else:
                # If already [0,1], use as-is; else soft-normalize
                dnorm = d if 0.0 <= d <= 1.0 else (d / (1.0 + d))
            norm_delays.append(np.clip(dnorm, 0.0, 1.0))

            # Overuse normalization
            if 'overuse' in ru:
                onorm = float(ru.get('overuse', 0.0))
            elif 'used' in ru and 'quota' in ru and ru['quota']:
                onorm = max(0.0, float(ru['used']) - float(ru['quota'])) / float(ru['quota'])
            else:
                onorm = 0.0
            norm_overuses.append(np.clip(onorm, 0.0, 1.0))

        norm_delay = float(np.mean(norm_delays)) if norm_delays else 0.0
        norm_overuse = float(np.mean(norm_overuses)) if norm_overuses else 0.0
        return max(0.0, 1.0 - (norm_delay + norm_overuse))


    def compute_fused_trust(self) -> float:
        """Compute fused trust based on the paper's formula."""
        tperf = np.clip(self.compute_performance_trust(), 0.0, 1.0)
        tfb = np.clip(self.compute_feedback_trust(), 0.0, 1.0)
        tbeh = np.clip(self.compute_behavioral_trust(), 0.0, 1.0)

        # Use a small epsilon to avoid division by zero or log(0) issues
        eps = 1e-9

        product = (tperf + eps) * (tfb + eps) * (tbeh + eps)
        arithmetic_mean = (tperf + tfb + tbeh) / 3.0

        # Denominator should not be zero
        if arithmetic_mean < eps:
            return 0.0

        fused = math.sqrt(product / arithmetic_mean)

        return float(np.clip(fused, 0.0, 1.0))

    def compute_anomaly_metrics(self, sigma_max: float = None, cmax: int = None) -> tuple:
        """
        Compute oscillation, variance, and change point scores from the trust sliding window.
        Args:
            sigma_max (float): Maximum expected standard deviation for normalization (default 0.25).
            cmax (int): Maximum number of change points for normalization (default 3).
        Returns:
            tuple: (oscillation_score, variance_score, change_point_score)
        """
        sigma_max = self.sigma_max if sigma_max is None else sigma_max
        cmax = self.cmax if cmax is None else cmax
        window = self.get_trust_window()
        k = len(window)

        if k < 2:
            return 0.0, 0.0, 0.0

        # Oscillation: number of trust flips / (k-1)
        flips = sum((window[i] - window[i-1]) * (window[i+1] - window[i]) < 0 for i in range(1, k-1))
        
        # --- CORRECTED LINE ---
        # The denominator is now (k-1) to match the paper's formula.
        osc = flips / (k - 1)
        
        # Variance: std / sigma_max
        var = float(np.std(window)) / sigma_max if sigma_max else 0.0
        
        # Change points: count large jumps / cmax
        change_points = sum(abs(window[i+1] - window[i]) > self.cp_threshold for i in range(k - 1))
        cp = change_points / cmax if cmax else 0.0
        
        return osc, var, cp

    def compute_anomaly_index(self, sigma_max: float = None, cmax: int = None) -> float:
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

    def compute_final_trust(self, sigma_max: float = None, cmax: int = None) -> float:
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
