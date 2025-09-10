import simpy
import logging
from typing import Dict, List, Any, Optional

from zta.zta_node import ZTANode
from zta.zta_policy import ZTAPolicy


class ZTAEnv:

    def __init__(
        self,
        scenario,
        policy: Optional[ZTAPolicy] = None,
        window_size: int = 5,
        logger: Optional[logging.Logger] = None

    ):

        self.scenario = scenario
        self.controller = simpy.Environment()
        self.logger = logger or logging.getLogger("ZTAEnv")

        self.nodes: Dict[str, ZTANode] = scenario.get_nodes()
        self.node_names: List[str] = list(self.nodes.keys())
        self.active_tasks: Dict[str, Any] = {}
        self.done_task_info: List[Dict[str, Any]] = []

        self.policy = policy or ZTAPolicy()
        self.window_size = window_size
        self.system_load = 'normal'
        self.threat_level = 'normal'
        self.criticality_map: Dict[str, str] = {}
        self.feedback_weights: Dict[str, float] = {name: 1.0 for name in self.node_names}

        self.quarantine_log: List[Dict[str, Any]] = []
        self.test_task_log: List[Dict[str, Any]] = []
        self.partial_assignment_log: List[Dict[str, Any]] = []
        self.monitoring_log: List[Dict[str, Any]] = []

    
    def run(self, until):

        self.controller.run(until=until)
    
    def reset(self):
        self.controller = simpy.Environment()
        for node in self.nodes.values():
            if hasattr(node, 'reset'):
                node.reset()
        self.active_tasks.clear()
        self.done_task_info.clear()
    
    def process(self,task, dst_name=None):
        self.controller.process(self.execute_task)
    
    def _execute_task(self, task, dst_name):

        yield self.controller.process(self._handle_task_transmission(task,dst_name))
        yield self.controlelr.proess(self._execute_task_on_node(task, dst_name))
    
    def _handle_task_transmission(self,task,dst_name):

        dst = self.nodes[dst_name]
        yield self.controller.process(dst.execute(task))
        self.done_task_info.append({"task": task, "node": dst_name})
        self.active_tasks.pop(task["id"],None)
    
    def _execute_task_on_node(self, task, dst_name):
        dst = self.nodes[dst_name]
        yield self.controller.process(dst.execute(task))
        self.done_task_info.append({"task": task, "node": dst_name})
        self.active_tasks.pop(task["id"], None)

    def update_system_load(self):
        loads = [getattr(node, "cpu_utilization", 0.5) for node in self.nodes.values()]
        avg_load = sum(loads) / len(loads) if loads else 0
        if avg_load > 0.8:
            self.system_load = "high"
        elif avg_load < 0.3:
            self.system_load = "low"
        else:
            self.system_load = "normal"

    def update_threat_level(self):
        anomalies = [getattr(node, "anomaly_score", 0.0) for node in self.nodes.values()]
        if any(a > 0.7 for a in anomalies):
            self.threat_level = "alert"
        else:
            self.threat_level = "normal"

    def get_task_criticality(self, task):
        return task.get("criticality", self.criticality_map.get(task.get("id"), "low"))

    def collect_feedback(self):
        return {name: node.give_feedback() for name, node in self.nodes.items()}

    def calculate_feedback_weights(self):
        feedback = self.collect_feedback()
        total = sum(feedback.values())
        for name, val in feedback.items():
            self.feedback_weights[name] = val / total if total > 0 else 1.0

    def update_node_trust(self):
        for node in self.nodes.values():
            node.update_trust()

    def assign_task(self, task):
        node_idx, action = self.policy.act(self, task)
        self.handle_policy_action(task, node_idx, action)

    def handle_policy_action(self, task, node_idx, action):
        node_name = self.node_names[node_idx]
        if action == "quarantine":
            self.log_quarantine(task, node_name)
        elif action == "test":
            self.log_test_task(task, node_name)
            self.process({"id": f"test-{task['id']}", "size": 1}, node_name)
        elif action == "partial":
            self.log_partial_assignment(task, node_name)
            self.process(task, node_name)
        elif action == "monitor":
            self.log_monitoring(task, node_name)
            self.process(task, node_name)
        else:
            self.process(task, node_name)

    def get_node(self, name):
        return self.nodes.get(name)

    def get_all_nodes(self):
        return list(self.nodes.values())

    def get_trust_matrix(self):
        return {name: getattr(node, "trust_scores", {}) for name, node in self.nodes.items()}

    def log_node_states(self):
        for name, node in self.nodes.items():
            info = node.node_info_str() if hasattr(node, "node_info_str") else "N/A"
            self.logger.info(f"{name}: {info}")

    def update_feedback_weights(self):
        self.calculate_feedback_weights()

    def log_quarantine(self, task, node_name):
        self.quarantine_log.append({"task": task, "node": node_name})

    def log_test_task(self, task, node_name):
        self.test_task_log.append({"task": task, "node": node_name})

    def log_partial_assignment(self, task, node_name):
        self.partial_assignment_log.append({"task": task, "node": node_name})

    def log_monitoring(self, task, node_name):
        self.monitoring_log.append({"task": task, "node": node_name})

        


