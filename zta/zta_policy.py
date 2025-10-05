# from typing import Any, Dict, List, Tuple

# class ZTAPolicy:
#     """
#     Zero Trust Architecture (ZTA) Policy for context-aware, rule-based task assignment.
#     Modular, extensible, and compatible with RayCloudSim's policy interface.
#     """
#     def __init__(self, config: Dict[str, Any] = None):
#         """
#         Optionally accept a config dict for custom thresholds/rules.
#         """
#         self.config = config or {}

#     def act(self, env, task) -> Tuple[int, str]:
#         """
#         Select a node for the given task based on ZTA rule-based policy.

#         Args:
#             env: The simulation environment (must provide access to nodes, system load, threat level, etc.)
#             task: The task to be assigned (must provide criticality, etc.)

#         Returns:
#             int: The index of the selected node (corresponds to env.scenario.node_id2name).
#         """
#         # 1. Gather context
#         system_load = self._get_system_load(env)
#         threat_level = self._get_threat_level(env)
#         criticality = self._get_task_criticality(task)

#         # 2. Gather trust/anomaly for each node
#         candidate_nodes, node_id2name = self._get_candidate_nodes(env)
#         node_scores = []
#         for idx, node in enumerate(candidate_nodes):
#             # Assume node is a ZTANode or compatible
#             t_final = node.compute_final_trust() if hasattr(node, 'compute_final_trust') else 0.0
#             anomaly = node.anomaly_index if hasattr(node, 'anomaly_index') else 0.0
#             node_scores.append({
#                 'node': node,
#                 't_final': t_final,
#                 'anomaly': anomaly,
#                 'idx': idx
#             })

#         # 3a. Tie-break if all trust equal/near-zero: prefer the source node,
#         # otherwise prefer the most idle node.
#         eps = 1e-9
#         all_zero = all(abs(s['t_final']) < eps for s in node_scores)
#         if all_zero:
#             # Prefer local execution if possible
#             src_name = getattr(task, 'src_name', None)
#             idx_by_name = {name: idx for idx, name in enumerate(node_id2name.values())}
#             if src_name in idx_by_name:
#                 return idx_by_name[src_name], 'full_assignment'
#             # Otherwise pick most idle (largest free_cpu_freq)
#             idx = max(range(len(node_scores)), key=lambda i: node_scores[i]['node'].free_cpu_freq)
#             return idx, 'full_assignment'

#         # 3b. Apply rule-based decision matrix
#         selected_node_idx, action = self._apply_rules(
#             node_scores, system_load, criticality, threat_level
#         )

#         # 4. Optionally log or return action type for monitoring
#         # print(f"Selected node: {selected_node_idx}, Action: {action}")

#         return selected_node_idx, action

#     # --- Helper methods below ---

#     def _get_system_load(self, env) -> str:
#         """Return 'high', 'low', or 'normal'. Honor env override if present."""
#         # Prefer explicit env state (supports demos/tests/overrides)
#         v = getattr(env, 'system_load', None)
#         if isinstance(v, str) and v in ('low', 'normal', 'high'):
#             return v
#         # Otherwise, infer from utilization
#         try:
#             nodes = self._get_candidate_nodes(env)[0]
#             avg_util = sum(1 - (n.free_cpu_freq / n.max_cpu_freq) for n in nodes) / len(nodes)
#             if avg_util > 0.8:
#                 return 'high'
#             elif avg_util < 0.3:
#                 return 'low'
#             else:
#                 return 'normal'
#         except Exception:
#             return 'normal'

#     def _get_threat_level(self, env) -> str:
#         """Return 'normal' or 'alert' based on environment state."""
#         # Example: Use an attribute or default to 'normal'
#         return getattr(env, 'threat_level', 'normal')

#     def _get_task_criticality(self, task) -> str:
#         """Return 'high' or 'low' based on task fields/attributes."""
#         if isinstance(task, dict):
#             return task.get('criticality', 'low')
#         return getattr(task, 'criticality', 'low')

#     def _get_candidate_nodes(self, env) -> Tuple[List[Any], Dict[int, str]]:
#         """
#         Return a list of candidate nodes and the node_id2name mapping.
#         Assumes env.scenario.get_nodes() returns a dict of name: node.
#         """
#         node_id2name = getattr(env.scenario, 'node_id2name', {})
#         nodes_dict = env.scenario.get_nodes()  # {name: node}
#         # Sort by node_id to match index order
#         sorted_nodes = [nodes_dict[node_id2name[i]] for i in range(len(node_id2name))]
#         return sorted_nodes, node_id2name

#     def _apply_rules(self, node_scores, system_load, criticality, threat_level):
#         """
#         Implements the rule-based matrix. Returns (selected_node_idx, action_type).
#         Supports external rule config via self.config['rules'].
#         """
#         rules = self.config.get('rules')
#         if rules:
#             # Determine action for each node
#             def match(rule, t, a) -> bool:
#                 cond = rule.get('when', {})
#                 tmin = cond.get('tmin', 0.0); tmax = cond.get('tmax', 1.0)
#                 amin = cond.get('amin', 0.0); amax = cond.get('amax', 1.0)
#                 if not (tmin <= t <= tmax and amin <= a <= amax):
#                     return False
#                 if 'load' in cond and cond['load'] != system_load:
#                     return False
#                 if 'criticality' in cond and cond['criticality'] != criticality:
#                     return False
#                 if 'threat' in cond and cond['threat'] != threat_level:
#                     return False
#                 return True

#             node_actions = []
#             for s in node_scores:
#                 t, a, idx = s['t_final'], s['anomaly'], s['idx']
#                 action = None
#                 for r in rules:
#                     if match(r, t, a):
#                         action = r.get('action', 'full_assignment')
#                         break
#                 if action is None:
#                     action = 'full_assignment'
#                 node_actions.append((idx, action, t))

#             # Choose best action/node by priority then by highest trust
#             priority = self.config.get('action_priority', [
#                 'quarantine', 'test_task_logging', 'partial_assignment', 'full_assignment_monitoring', 'full_assignment'
#             ])
#             pr_index = {name: i for i, name in enumerate(priority)}
#             # Optionally exclude quarantine if any non-quarantine exists
#             if self.config.get('allow_quarantine_with_alternatives', True):
#                 candidates = node_actions
#             else:
#                 non_quarantine = [na for na in node_actions if na[1] != 'quarantine']
#                 candidates = non_quarantine if non_quarantine else node_actions
#             best = min(candidates, key=lambda na: (pr_index.get(na[1], 999), -na[2]))
#             return best[0], best[1]

#         # Built-in default rule set if no external rules provided
#         for score in node_scores:
#             t = score['t_final']
#             a = score['anomaly']
#             idx = score['idx']
#             if t > 0.8 and a < 0.3 and threat_level == 'normal':
#                 return idx, 'full_assignment'
#             elif 0.6 <= t <= 0.8 and criticality == 'low' and threat_level == 'normal':
#                 return idx, 'test_task_logging'
#             elif t < 0.5 and a > 0.5:
#                 return idx, 'quarantine'
#             elif 0.5 <= t <= 0.7 and a < 0.3 and criticality == 'high' and threat_level == 'alert':
#                 return idx, 'partial_assignment'
#             elif t > 0.7 and a < 0.2 and system_load == 'high' and criticality == 'low' and threat_level == 'normal':
#                 return idx, 'full_assignment_monitoring'
#         best_idx = max(range(len(node_scores)), key=lambda i: node_scores[i]['t_final'])
#         return best_idx, 'full_assignment'


from typing import Any, Dict, List, Tuple

class ZTAPolicy:
    """
    Zero Trust Architecture (ZTA) Policy for context-aware, rule-based task assignment.
    Implements rule-based decisions based on trust, anomaly, load, criticality, and threat.
    Compatible with RayCloudSim's policy interface.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    def act(self, env, task) -> Tuple[int, str]:
        system_load = self._get_system_load(env)
        threat_level = self._get_threat_level(env)
        criticality = self._get_task_criticality(task)

        candidate_nodes, node_id2name = self._get_candidate_nodes(env)
        node_scores = []
        for idx, node in enumerate(candidate_nodes):
            t_final = node.compute_final_trust() if hasattr(node, 'compute_final_trust') else 0.0
            anomaly = node.anomaly_index if hasattr(node, 'anomaly_index') else 0.0
            node_scores.append({
                'node': node,
                't_final': t_final,
                'anomaly': anomaly,
                'idx': idx
            })

        # If all trust scores are ~0, prefer source node or most idle node
        eps = 1e-9
        if all(abs(s['t_final']) < eps for s in node_scores):
            src_name = getattr(task, 'src_name', None)
            idx_by_name = {name: idx for idx, name in enumerate(node_id2name.values())}
            if src_name in idx_by_name:
                return idx_by_name[src_name], 'full_assignment'
            idx = max(range(len(node_scores)), key=lambda i: node_scores[i]['node'].free_cpu_freq)
            return idx, 'full_assignment'

        # Apply ZTA rules
        selected_node_idx, action = self._apply_rules(
            node_scores, system_load, criticality, threat_level
        )
        return selected_node_idx, action

    # ---------------------- Helpers ----------------------

    def _get_system_load(self, env) -> str:
        v = getattr(env, 'system_load', None)
        if isinstance(v, str) and v in ('low', 'normal', 'high'):
            return v
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
        return getattr(env, 'threat_level', 'normal')

    def _get_task_criticality(self, task) -> str:
        if isinstance(task, dict):
            return task.get('criticality', 'low')
        return getattr(task, 'criticality', 'low')

    def _get_candidate_nodes(self, env) -> Tuple[List[Any], Dict[int, str]]:
        node_id2name = getattr(env.scenario, 'node_id2name', {})
        nodes_dict = env.scenario.get_nodes()
        sorted_nodes = [nodes_dict[node_id2name[i]] for i in range(len(node_id2name))]
        return sorted_nodes, node_id2name

    def _apply_rules(self, node_scores, system_load, criticality, threat_level):
        """
        Implements rule-based task assignment from ZeroTrust paper.
        Returns (node_idx, action_type).
        """
        for score in node_scores:
            t, a, idx = score['t_final'], score['anomaly'], score['idx']

            # Rule 1: Full Assignment
            if t > 0.8 and a < 0.3 and threat_level == 'normal':
                return idx, 'full_assignment'

            # Rule 2: Test Task + Logging
            elif 0.6 <= t <= 0.8 and system_load == 'low' and criticality == 'high' and threat_level == 'normal':
                return idx, 'test_task_logging'

            # Rule 3: Quarantine
            elif t < 0.5 and a > 0.5:
                return idx, 'quarantine'

            # Rule 4: Partial Assignment
            elif 0.5 <= t <= 0.7 and a < 0.3 and system_load == 'high' and criticality == 'high' and threat_level == 'alert':
                return idx, 'partial_assignment'

            # Rule 5: Full Assignment with Monitoring
            elif t > 0.7 and a < 0.2 and system_load == 'high' and criticality == 'low' and threat_level == 'normal':
                return idx, 'full_assignment_monitoring'

        # Default: choose highest-trust node
        best_idx = max(range(len(node_scores)), key=lambda i: node_scores[i]['t_final'])
        return best_idx, 'full_assignment'
