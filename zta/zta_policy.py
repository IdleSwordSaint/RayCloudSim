from typing import Any, Dict, List, Tuple

class ZTAPolicy:
    """
    Zero Trust Architecture (ZTA) Policy for context-aware, rule-based task assignment.
    Modular, extensible, and compatible with RayCloudSim's policy interface.
    """
    def __init__(self, config: Dict[str, Any] = None):
        """
        Optionally accept a config dict for custom thresholds/rules.
        """
        self.config = config or {}

    def act(self, env, task) -> int:
        """
        Select a node for the given task based on ZTA rule-based policy.

        Args:
            env: The simulation environment (must provide access to nodes, system load, threat level, etc.)
            task: The task to be assigned (must provide criticality, etc.)

        Returns:
            int: The index of the selected node (corresponds to env.scenario.node_id2name).
        """
        # 1. Gather context
        system_load = self._get_system_load(env)
        threat_level = self._get_threat_level(env)
        criticality = self._get_task_criticality(task)

        # 2. Gather trust/anomaly for each node
        candidate_nodes, node_id2name = self._get_candidate_nodes(env)
        node_scores = []
        for idx, node in enumerate(candidate_nodes):
            # Assume node is a ZTANode or compatible
            t_final = node.compute_final_trust() if hasattr(node, 'compute_final_trust') else 0.0
            anomaly = node.anomaly_index if hasattr(node, 'anomaly_index') else 0.0
            node_scores.append({
                'node': node,
                't_final': t_final,
                'anomaly': anomaly,
                'idx': idx
            })

        # 3. Apply rule-based decision matrix
        selected_node_idx, action = self._apply_rules(
            node_scores, system_load, criticality, threat_level
        )

        # 4. Optionally log or return action type for monitoring
        # print(f"Selected node: {selected_node_idx}, Action: {action}")

        return selected_node_idx

    # --- Helper methods below ---

    def _get_system_load(self, env) -> str:
        """Return 'high', 'low', or 'normal' based on environment metrics."""
        # Example: Use average CPU utilization across all nodes
        try:
            nodes = self._get_candidate_nodes(env)[0]
            avg_util = sum(1 - (n.free_cpu_freq / n.max_cpu_freq) for n in nodes) / len(nodes)
            if avg_util > 0.8:
                return 'high'
            elif avg_util < 0.3:
                return 'low'
            else:
                return 'normal'
        except Exception:
            return 'normal'

    def _get_threat_level(self, env) -> str:
        """Return 'normal' or 'alert' based on environment state."""
        # Example: Use an attribute or default to 'normal'
        return getattr(env, 'threat_level', 'normal')

    def _get_task_criticality(self, task) -> str:
        """Return 'high' or 'low' based on task attributes."""
        # Example: Use a 'criticality' attribute or default to 'low'
        return getattr(task, 'criticality', 'low')

    def _get_candidate_nodes(self, env) -> Tuple[List[Any], Dict[int, str]]:
        """
        Return a list of candidate nodes and the node_id2name mapping.
        Assumes env.scenario.get_nodes() returns a dict of name: node.
        """
        node_id2name = getattr(env.scenario, 'node_id2name', {})
        nodes_dict = env.scenario.get_nodes()  # {name: node}
        # Sort by node_id to match index order
        sorted_nodes = [nodes_dict[node_id2name[i]] for i in range(len(node_id2name))]
        return sorted_nodes, node_id2name

    def _apply_rules(self, node_scores, system_load, criticality, threat_level):
        """
        Implements the rule-based matrix. Returns (selected_node_idx, action_type).
        """
        # You can expand this logic as needed for your full rule matrix
        for score in node_scores:
            t = score['t_final']
            a = score['anomaly']
            idx = score['idx']
            # Example rules (expand as per your matrix)
            if t > 0.8 and a < 0.3 and threat_level == 'normal':
                return idx, 'full_assignment'
            elif 0.6 <= t <= 0.8 and criticality == 'low' and threat_level == 'normal':
                return idx, 'test_task_logging'
            elif t < 0.5 and a > 0.5:
                return idx, 'quarantine'
            elif 0.5 <= t <= 0.7 and a < 0.3 and criticality == 'high' and threat_level == 'alert':
                return idx, 'partial_assignment'
            elif t > 0.7 and a < 0.2 and system_load == 'high' and criticality == 'low' and threat_level == 'normal':
                return idx, 'full_assignment_monitoring'
        # Default: pick the node with highest t_final
        best_idx = max(range(len(node_scores)), key=lambda i: node_scores[i]['t_final'])
        return best_idx, 'default' 