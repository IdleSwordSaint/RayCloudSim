# import os
# import sys
# import json
# from typing import Any, Optional, Dict, List
# import simpy
# import random

# from core.infrastructure import DataFlow, Link
# from .zta_policy import ZTAPolicy
# from .zta_node import ZTANode

# def _task_field(task: Any, key: str, default=None):
#     # Supports dict-based tasks and objects with attributes
#     if isinstance(task, dict):
#         return task.get(key, default)
#     return getattr(task, key, default)

# class ZTAEnv:
#     """
#     SimPy-based ZTA environment (friend-authored structure, corrected).

#     - Maintains its own SimPy environment.
#     - Uses scenario.infrastructure to compute network paths and latencies.
#     - Applies ZTAPolicy to decide assignment and logs state per task.
#     - Updates ZTANode trust/anomaly on completion.
#     """

#     def __init__(
#         self,
#         scenario,
#         policy: Optional[ZTAPolicy] = None,
#         window_size: int = 5,
#         logger: Optional[Any] = None,
#     ):
#         self.scenario = scenario
#         self.controller = simpy.Environment()
#         self.logger = logger
#         # Node registry
#         self.nodes: Dict[str, ZTANode] = scenario.get_nodes()  # type: ignore
#         self.node_names: List[str] = list(self.nodes.keys())
#         self.active_tasks: Dict[str, simpy.events.Event] = {}
#         self.done_task_info: List[Dict[str, Any]] = []
#         self.policy = policy or ZTAPolicy()
#         self.window_size = window_size
#         self.system_load = 'normal'
#         self.threat_level = 'normal'
#         self.criticality_map: Dict[str, str] = {}
#         self.feedback_weights: Dict[str, float] = {name: 1.0 for name in self.node_names}
#         # Logs per action type
#         self.quarantine_log: List[Dict[str, Any]] = []
#         self.test_task_log: List[Dict[str, Any]] = []
#         self.partial_assignment_log: List[Dict[str, Any]] = []
#         self.monitoring_log: List[Dict[str, Any]] = []
#         # Optional state overrides for demos/tests
#         self._override_system_load: Optional[str] = None
#         self._override_threat_level: Optional[str] = None

#     @property
#     def now(self) -> float:
#         return self.controller.now

#     # --- Control ---
#     def run(self, until):
#         self.controller.run(until=until)

#     def reset(self):
#         self.controller = simpy.Environment()
#         for node in self.nodes.values():
#             if hasattr(node, 'reset'):
#                 node.reset()
#         self.active_tasks.clear()
#         self.done_task_info.clear()

#     # --- Processing pipeline ---
#     def process(self, task: Any, dst_name: Optional[str] = None):
#         task_id = str(_task_field(task, 'task_id', _task_field(task, 'id', 'unknown')))
#         self.active_tasks[task_id] = self.controller.process(self._execute_task(task, dst_name))

#     def _execute_task(self, task: Any, dst_name: Optional[str]):
#         src_name = _task_field(task, 'src_name', _task_field(task, 'src', None))
#         # Decide destination via policy if not provided
#         if dst_name is None:
#             idx, action = self.policy.act(self, task)
#             # Map policy index to node name consistently with policy's indexing
#             name_map = getattr(self.scenario, 'node_id2name', {})
#             if name_map and idx in name_map:
#                 dst_name = name_map[idx]
#             else:
#                 # Fallback to list order if mapping not available
#                 dst_name = self.node_names[idx % len(self.node_names)]
#         else:
#             action = 'full_assignment'

#         # Update state and print
#         criticality = self.get_task_criticality(task)
#         self.update_system_load()
#         self.update_threat_level()
#         self._print_state(criticality, action, dst_name)

#         # Transmission
#         if src_name and dst_name and src_name != dst_name:
#             yield from self._handle_task_transmission(task, src_name, dst_name)

#         # Execution
#         yield from self._execute_task_on_node(task, dst_name)

#     def _handle_task_transmission(self, task: Any, src_name: str, dst_name: str):
#         task_size = _task_field(task, 'task_size', _task_field(task, 'size', 0))
#         bit_rate = _task_field(task, 'trans_bit_rate', _task_field(task, 'bitrate', 1))
#         try:
#             links_in_path = self.scenario.infrastructure.get_shortest_links(src_name, dst_name)
#         except Exception:
#             return

#         base_latency = sum(link.base_latency for link in links_in_path if isinstance(link, Link))
#         hops = sum(1 for link in links_in_path if isinstance(link, Link))
#         trans_time = base_latency + (task_size / max(1, bit_rate)) * hops

#         df = DataFlow(bit_rate)
#         try:
#             df.allocate([l for l in links_in_path if isinstance(l, Link)])
#         except Exception:
#             pass
#         yield self.controller.timeout(trans_time)
#         try:
#             df.deallocate()
#         except Exception:
#             pass

#     def _execute_task_on_node(self, task: Any, dst_name: str):
#         dst = self.nodes[dst_name]
#         task_size = _task_field(task, 'task_size', _task_field(task, 'size', 0))
#         cycles_per_bit = _task_field(task, 'cycles_per_bit', 10)
#         ddl = _task_field(task, 'ddl', -1)
#         exe_time = (task_size * cycles_per_bit) / max(1, dst.max_cpu_freq)

#         prev = dst.free_cpu_freq
#         dst.free_cpu_freq = 0
#         yield self.controller.timeout(exe_time)
#         dst.free_cpu_freq = prev

#         # Trust update after completion
#         criticality = self.get_task_criticality(task)
#         overuse = 0.0
#         if getattr(dst, 'malicious_type', None):
#             overuse = 0.6 + 0.3 * random.random() if random.random() < 0.5 else 0.0

#         # Normalize delay vs ddl (fallback to soft normalization if ddl unknown)
#     # Normalize delay vs ddl (fallback to soft normalization if ddl unknown)
#         if ddl and ddl > 0:
#             delay_norm = exe_time / ddl    # <-- changed, removed min(1.0, ...)
#         else:
#             delay_norm = exe_time / (1.0 + exe_time)

#         # Simulate success or failure
#         success = random.random() > 0.2   # 80% success rate

#         dst.add_task_result(
#             task_id=str(_task_field(task, 'task_id', _task_field(task, 'id', 'unknown'))),
#             success=success,
#             delay=delay_norm,
#             resource_usage={"overuse": overuse},
#             criticality=criticality,
#             timestamp=self.now,
#         )
#         dst.compute_final_trust()
#         self.done_task_info.append({"task": task, "node": dst_name})
#         self.active_tasks.pop(str(_task_field(task, 'task_id', _task_field(task, 'id', 'unknown'))), None)

#     # --- State management ---
#     def update_system_load(self):
#         if self._override_system_load is not None:
#             self.system_load = self._override_system_load
#             return
#         loads = [1 - (node.free_cpu_freq / node.max_cpu_freq) for node in self.nodes.values()]
#         avg = sum(loads) / len(loads) if loads else 0
#         self.system_load = 'high' if avg > 0.8 else 'low' if avg < 0.3 else 'normal'

#     def update_threat_level(self):
#         if self._override_threat_level is not None:
#             self.threat_level = self._override_threat_level
#             return
#         anomalies = [getattr(n, 'anomaly_index', 0.0) for n in self.nodes.values()]
#         self.threat_level = 'alert' if any(a > 0.7 for a in anomalies) else 'normal'

#     def get_task_criticality(self, task: Any):
#         return _task_field(task, 'criticality', self.criticality_map.get(_task_field(task, 'id', ''), 'low'))

#     # --- Feedback/trust bookkeeping ---
#     def collect_feedback(self):
#         return {name: getattr(node, 'compute_feedback_trust', lambda: 0.5)() for name, node in self.nodes.items()}

#     def calculate_feedback_weights(self):
#         feedback = self.collect_feedback()
#         total = sum(feedback.values())
#         for name, val in feedback.items():
#             self.feedback_weights[name] = val / total if total > 0 else 1.0

#     def update_node_trust(self):
#         for node in self.nodes.values():
#             if hasattr(node, 'compute_final_trust'):
#                 node.compute_final_trust()

#     # --- Policy orchestration ---
#     def assign_task(self, task: Any):
#         idx, action = self.policy.act(self, task)
#         self.handle_policy_action(task, idx, action)

#     def handle_policy_action(self, task: Any, node_idx: int, action: str):
#         node_name = self.node_names[node_idx]
#         if action == 'quarantine':
#             self.log_quarantine(task, node_name)
#         elif action in ('test_task_logging', 'test'):
#             self.log_test_task(task, node_name)
#             self.process({"id": f"test-{_task_field(task, 'id', _task_field(task, 'task_id', '0'))}", "size": 1, "cycles_per_bit": 1, "src": _task_field(task, 'src_name', _task_field(task, 'src', node_name))}, node_name)
#         elif action in ('partial_assignment', 'partial'):
#             self.log_partial_assignment(task, node_name)
#             self.process(task, node_name)
#         elif action in ('full_assignment_monitoring', 'monitor'):
#             self.log_monitoring(task, node_name)
#             self.process(task, node_name)
#         else:
#             self.process(task, node_name)

#     # --- Logging helpers ---
#     def _print_state(self, criticality: str, action: str, dst_name: str):
#         # Best-effort to include chosen node's trust/anomaly for transparency
#         node = self.get_node(dst_name)
#         t_final = getattr(node, 'compute_final_trust', lambda: None)()
#         anomaly = getattr(node, 'anomaly_index', None)
#         msg = (
#             f"state | load={self.system_load} threat={self.threat_level} criticality={criticality} "
#             f"action={action} dst={dst_name} t_final={t_final if t_final is not None else 'NA'} "
#             f"anomaly={anomaly if anomaly is not None else 'NA'}"
#         )
#         print(msg)
#         try:
#             if self.logger:
#                 self.logger.info(msg)
#         except Exception:
#             pass

#     # --- Introspection / logs ---
#     def get_node(self, name):
#         return self.nodes.get(name)

#     def get_all_nodes(self):
#         return list(self.nodes.values())

#     def get_trust_matrix(self):
#         return {name: getattr(node, "trust_sliding_window", []) for name, node in self.nodes.items()}

#     def log_node_states(self):
#         for name, node in self.nodes.items():
#             info = node.node_info_str() if hasattr(node, "node_info_str") else "N/A"
#             try:
#                 if self.logger:
#                     self.logger.info(f"{name}: {info}")
#             except Exception:
#                 print(f"{name}: {info}")

#     def update_feedback_weights(self):
#         self.calculate_feedback_weights()

#     def log_quarantine(self, task, node_name):
#         self.quarantine_log.append({"task": task, "node": node_name})

#     def log_test_task(self, task, node_name):
#         self.test_task_log.append({"task": task, "node": node_name})

#     def log_partial_assignment(self, task, node_name):
#         self.partial_assignment_log.append({"task": task, "node": node_name})

#     def log_monitoring(self, task, node_name):
#         self.monitoring_log.append({"task": task, "node": node_name})

#     # --- Overrides for demos ---
#     def set_overrides(self, system_load: Optional[str] = None, threat: Optional[str] = None):
#         if system_load is not None:
#             assert system_load in ('low', 'normal', 'high')
#             self._override_system_load = system_load
#         if threat is not None:
#             assert threat in ('normal', 'alert')
#             self._override_threat_level = threat
#     def clear_overrides(self):
#         self._override_system_load = None
#         self._override_threat_level = None


# File: zta/env.py
import os
import sys
import json
from typing import Any, Optional, Dict, List
import simpy
import random

from core.infrastructure import DataFlow, Link
from .zta_policy import ZTAPolicy
from .zta_node import ZTANode

def _task_field(task: Any, key: str, default=None):
    # Supports dict-based tasks and objects with attributes
    if isinstance(task, dict):
        return task.get(key, default)
    return getattr(task, key, default)

class ZTAEnv:
    """
    SimPy-based ZTA environment (friend-authored structure, corrected).

    - Maintains its own SimPy environment.
    - Uses scenario.infrastructure to compute network paths and latencies.
    - Applies ZTAPolicy to decide assignment and logs state per task.
    - Updates ZTANode trust/anomaly on completion.
    """

    def __init__(
        self,
        scenario,
        policy: Optional[ZTAPolicy] = None,
        window_size: int = 5,
        logger: Optional[Any] = None,
        config_file: Optional[str] = None,
    ):
        self.scenario = scenario
        self.controller = simpy.Environment()
        self.logger = logger
        # Node registry
        self.nodes: Dict[str, ZTANode] = scenario.get_nodes()  # type: ignore
        self.node_names: List[str] = list(self.nodes.keys())
        self.active_tasks: Dict[str, simpy.events.Event] = {}
        self.done_task_info: List[Dict[str, Any]] = []
        self.policy = policy or ZTAPolicy()
        self.window_size = window_size
        self.system_load = 'normal'
        self.threat_level = 'normal'
        self.criticality_map: Dict[str, str] = {}
        self.feedback_weights: Dict[str, float] = {name: 1.0 for name in self.node_names}
        # Logs per action type
        self.quarantine_log: List[Dict[str, Any]] = []
        self.test_task_log: List[Dict[str, Any]] = []
        self.partial_assignment_log: List[Dict[str, Any]] = []
        self.monitoring_log: List[Dict[str, Any]] = []
        # Optional state overrides for demos/tests
        self._override_system_load: Optional[str] = None
        self._override_threat_level: Optional[str] = None

        # --- ADDED: Dictionary to count policy actions ---
        self.action_counts: Dict[str, int] = {}

        # --- Visualization config (mirror core/env.py minimal bits) ---
        # Load ZTA env-config if provided; default to zta/configs/env_config.json
        # This enables recording per-tick frame info and later video export via core.vis
        self.refresh_rate = 1
        if config_file is None:
            # default to zta/configs/env_config.json (relative to this file)
            config_file = os.path.join(os.path.dirname(__file__), 'configs', 'env_config.json')
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except Exception:
            # Fallback minimal config if missing; visualization remains off
            self.config = {
                "Basic": {"VisFrame": "off", "Train": "off", "Test": "off"},
                "VisFrame": {
                    "LogInfoPath": "logs/vis_zta",
                    "LogFramesPath": "logs/vis_zta/frames",
                    "TargetNodeList": []
                },
            }

        # Validate and start recorder if enabled
        if self.config.get('Basic', {}).get('VisFrame') == 'on':
            self._validate_config()
            self._setup_visualization_directories()
            self.frame_info: Dict[float, dict] = {}
            self.frame_recorder = self.controller.process(self._record_frame_info())

    @property
    def now(self) -> float:
        return self.controller.now

    # --- Control ---
    def run(self, until):
        self.controller.run(until=until)

    def reset(self):
        self.controller = simpy.Environment()
        for node in self.nodes.values():
            if hasattr(node, 'reset'):
                node.reset()
        self.active_tasks.clear()
        self.done_task_info.clear()

    # --- Processing pipeline ---
    def process(self, task: Any, dst_name: Optional[str] = None):
        task_id = str(_task_field(task, 'task_id', _task_field(task, 'id', 'unknown')))
        self.active_tasks[task_id] = self.controller.process(self._execute_task(task, dst_name))

    def _execute_task(self, task: Any, dst_name: Optional[str]):
        src_name = _task_field(task, 'src_name', _task_field(task, 'src', None))
        
        # Decide destination via policy if not provided
        if dst_name is None:
            idx, action = self.policy.act(self, task)
            # Map policy index to node name consistently with policy's indexing
            name_map = getattr(self.scenario, 'node_id2name', {})
            if name_map and idx in name_map:
                dst_name = name_map[idx]
            else:
                # Fallback to list order if mapping not available
                dst_name = self.node_names[idx % len(self.node_names)]
        else:
            action = 'full_assignment'

        # --- ADDED: Increment the counter for the chosen action ---
        self.action_counts[action] = self.action_counts.get(action, 0) + 1

        # Update state and print
        criticality = self.get_task_criticality(task)
        self.update_system_load()
        self.update_threat_level()
        self._print_state(criticality, action, dst_name)

        # Handle Quarantine action: if a node is quarantined, no task is processed.
        if action == 'quarantine':
            self.log_quarantine(task, dst_name)
            return # Stop further processing for this task

        # Transmission
        if src_name and dst_name and src_name != dst_name:
            yield from self._handle_task_transmission(task, src_name, dst_name)

        # Execution
        yield from self._execute_task_on_node(task, dst_name)

    def _handle_task_transmission(self, task: Any, src_name: str, dst_name: str):
        task_size = _task_field(task, 'task_size', _task_field(task, 'size', 0))
        bit_rate = _task_field(task, 'trans_bit_rate', _task_field(task, 'bitrate', 1))
        try:
            links_in_path = self.scenario.infrastructure.get_shortest_links(src_name, dst_name)
        except Exception:
            return

        base_latency = sum(link.base_latency for link in links_in_path if isinstance(link, Link))
        hops = sum(1 for link in links_in_path if isinstance(link, Link))
        trans_time = base_latency + (task_size / max(1, bit_rate)) * hops

        df = DataFlow(bit_rate)
        try:
            df.allocate([l for l in links_in_path if isinstance(l, Link)])
        except Exception:
            pass
        yield self.controller.timeout(trans_time)
        try:
            df.deallocate()
        except Exception:
            pass

    def _execute_task_on_node(self, task: Any, dst_name: str):
        dst = self.nodes[dst_name]
        task_size = _task_field(task, 'task_size', _task_field(task, 'size', 0))
        cycles_per_bit = _task_field(task, 'cycles_per_bit', 10)
        ddl = _task_field(task, 'ddl', -1)
        exe_time = (task_size * cycles_per_bit) / max(1, dst.max_cpu_freq)

        # Track the task as ACTIVE on the destination node so the
        # frame overlay can display it while executing.
        task_id_str = str(_task_field(task, 'task_id', _task_field(task, 'id', 'unknown')))
        try:
            if task_id_str not in getattr(dst, 'active_task_ids', []):
                dst.active_task_ids.append(task_id_str)
        except Exception:
            pass

        prev = dst.free_cpu_freq
        dst.free_cpu_freq = 0
        yield self.controller.timeout(exe_time)
        dst.free_cpu_freq = prev

        # --- MODIFIED: More realistic behavior for malicious vs. normal nodes ---
        criticality = self.get_task_criticality(task)
        overuse = 0.0
        if getattr(dst, 'malicious_type', None):
            success = random.random() > 0.8  # 80% failure rate for malicious nodes
            overuse = 0.5 + 0.5 * random.random() # High resource overuse
        else:
            success = random.random() > 0.1 # 90% success rate for normal nodes

        if ddl and ddl > 0:
            delay_norm = exe_time / ddl
        else:
            delay_norm = exe_time / (1.0 + exe_time)

        dst.add_task_result(
            task_id=task_id_str,
            success=success,
            delay=delay_norm,
            resource_usage={"overuse": overuse},
            criticality=criticality,
            timestamp=self.now,
        )
        dst.compute_final_trust()
        self.done_task_info.append({"task": task, "node": dst_name})
        self.active_tasks.pop(task_id_str, None)
        # Remove from ACTIVE now that execution has finished
        try:
            if task_id_str in getattr(dst, 'active_task_ids', []):
                dst.active_task_ids.remove(task_id_str)
        except Exception:
            pass

    # --- State management ---
    def update_system_load(self):
        if self._override_system_load is not None:
            self.system_load = self._override_system_load
            return
        # Calculate load based on nodes that are NOT free
        busy_nodes = sum(1 for node in self.nodes.values() if node.free_cpu_freq < node.max_cpu_freq)
        load_ratio = busy_nodes / len(self.nodes) if self.nodes else 0
        self.system_load = 'high' if load_ratio > 0.5 else 'low' if load_ratio < 0.2 else 'normal'

    def update_threat_level(self):
        if self._override_threat_level is not None:
            self.threat_level = self._override_threat_level
            return
        anomalies = [getattr(n, 'anomaly_index', 0.0) for n in self.nodes.values()]
        self.threat_level = 'alert' if any(a > 0.7 for a in anomalies) else 'normal'

    def get_task_criticality(self, task: Any):
        return _task_field(task, 'criticality', self.criticality_map.get(_task_field(task, 'id', ''), 'low'))

    # --- Feedback/trust bookkeeping ---
    def collect_feedback(self):
        return {name: getattr(node, 'compute_feedback_trust', lambda: 0.5)() for name, node in self.nodes.items()}

    def calculate_feedback_weights(self):
        feedback = self.collect_feedback()
        total = sum(feedback.values())
        for name, val in feedback.items():
            self.feedback_weights[name] = val / total if total > 0 else 1.0

    def update_node_trust(self):
        for node in self.nodes.values():
            if hasattr(node, 'compute_final_trust'):
                node.compute_final_trust()

    # --- Policy orchestration ---
    def assign_task(self, task: Any):
        idx, action = self.policy.act(self, task)
        self.handle_policy_action(task, idx, action)

    def handle_policy_action(self, task: Any, node_idx: int, action: str):
        node_name = self.node_names[node_idx]
        if action == 'quarantine':
            self.log_quarantine(task, node_name)
        elif action in ('test_task_logging', 'test'):
            self.log_test_task(task, node_name)
            self.process({"id": f"test-{_task_field(task, 'id', _task_field(task, 'task_id', '0'))}", "size": 1, "cycles_per_bit": 1, "src": _task_field(task, 'src_name', _task_field(task, 'src', node_name))}, node_name)
        elif action in ('partial_assignment', 'partial'):
            self.log_partial_assignment(task, node_name)
            self.process(task, node_name)
        elif action in ('full_assignment_monitoring', 'monitor'):
            self.log_monitoring(task, node_name)
            self.process(task, node_name)
        else:
            self.process(task, node_name)

    # --- Logging helpers ---
    def _print_state(self, criticality: str, action: str, dst_name: str):
        # --- MODIFIED: Improved print format and safety check ---
        node = self.get_node(dst_name)
        if not node:
            # This can happen if the policy tries to assign to a quarantined node
            print(f"state @ t={self.now:.2f} | action={action} dst={dst_name} (Node not available or quarantined)")
            return
            
        t_final = getattr(node, 'compute_final_trust', lambda: 0.0)()
        anomaly = getattr(node, 'anomaly_index', 0.0)
        msg = (
            f"state @ t={self.now:.2f} | load={self.system_load} threat={self.threat_level} crit={criticality} "
            f"action={action} dst={dst_name} t_final={t_final:.4f} "
            f"anomaly={anomaly:.4f}"
        )
        print(msg)
        try:
            if self.logger:
                self.logger.info(msg)
        except Exception:
            pass

    # --- Introspection / logs ---
    def get_node(self, name):
        return self.nodes.get(name)

    def get_all_nodes(self):
        return list(self.nodes.values())

    def get_trust_matrix(self):
        return {name: getattr(node, "trust_sliding_window", []) for name, node in self.nodes.items()}

    def log_node_states(self):
        for name, node in self.nodes.items():
            info = node.node_info_str() if hasattr(node, "node_info_str") else "N/A"
            try:
                if self.logger:
                    self.logger.info(f"{name}: {info}")
            except Exception:
                print(f"{name}: {info}")

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

    # --- Overrides for demos ---
    def set_overrides(self, system_load: Optional[str] = None, threat: Optional[str] = None):
        if system_load is not None:
            assert system_load in ('low', 'normal', 'high')
            self._override_system_load = system_load
        if threat is not None:
            assert threat in ('normal', 'alert')
            self._override_threat_level = threat
    def clear_overrides(self):
        self._override_system_load = None
        self._override_threat_level = None

    # --- Visualization helpers (mirror of core style) ---
    def _validate_config(self) -> None:
        try:
            max_nodes = 20
            target_nodes = len(self.config['VisFrame'].get('TargetNodeList', []))
            assert target_nodes <= max_nodes
        except Exception:
            pass

    def _setup_visualization_directories(self) -> None:
        os.makedirs(self.config['VisFrame']['LogInfoPath'], exist_ok=True)
        os.makedirs(self.config['VisFrame']['LogFramesPath'], exist_ok=True)

    def _record_frame_info(self):
        """Record per-tick metrics for video frames.

        Node metric can be configured via env.config['VisFrame']['NodeMetric']:
          - 'cpu' (default fallback): CPU utilization ratio in [0,1]
          - 'final_trust': fused_trust/(1+anomaly) in [0,1]
          - 'anomaly': current anomaly index clipped to [0,1]
        """
        while True:
            node_metric = (self.config.get('VisFrame', {}).get('NodeMetric') or 'final_trust').lower()
            nodes = self.scenario.get_nodes()
            if node_metric == 'final_trust':
                node_vals = {}
                for k, n in nodes.items():
                    try:
                        fused = n.compute_fused_trust()
                        a = float(getattr(n, 'anomaly_index', 0.0))
                        node_vals[k] = max(0.0, min(1.0, fused / (1.0 + a)))
                    except Exception:
                        node_vals[k] = 0.0
            elif node_metric == 'anomaly':
                node_vals = {k: float(max(0.0, min(1.0, getattr(n, 'anomaly_index', 0.0)))) for k, n in nodes.items()}
            else:
                # cpu utilization ratio
                node_vals = {k: n.quantify_cpu_freq() for k, n in nodes.items()}

            self.frame_info[self.now] = {
                'node': node_vals,
                'edge': {str(k): l.quantify_bandwidth() for k, l in self.scenario.get_links().items()},
            }
            # include tracked nodes' metrics for overlay panel
            tgt = self.config.get('VisFrame', {}).get('TargetNodeList', [])
            if tgt:
                overlay = {}
                for name in tgt:
                    if name not in nodes:
                        continue
                    n = nodes[name]
                    try:
                        fused = n.compute_fused_trust()
                        a = float(getattr(n, 'anomaly_index', 0.0))
                        t_final = max(0.0, min(1.0, fused / (1.0 + a)))
                        # Fill the right bracket with the node's active tasks.
                        # If none are active at this tick, fall back to queued tasks
                        # so the panel remains informative.
                        active = [str(x) for x in getattr(n, 'active_task_ids', [])]
                        if not active:
                            try:
                                active = [str(x) for x in getattr(getattr(n, 'task_buffer', None), 'task_ids', [])]
                            except Exception:
                                active = []
                        overlay[name] = [[f"t:{t_final:.2f}", f"a:{a:.2f}"], active]
                    except Exception:
                        # Still try to report active/queued tasks if available
                        active = [str(x) for x in getattr(n, 'active_task_ids', [])]
                        if not active:
                            try:
                                active = [str(x) for x in getattr(getattr(n, 'task_buffer', None), 'task_ids', [])]
                            except Exception:
                                active = []
                        overlay[name] = [["t:NA", "a:NA"], active]
                self.frame_info[self.now]['target'] = overlay
            yield self.controller.timeout(self.refresh_rate)

    def close(self):
        """Flush frame_info to JSON and stop recorder if visualization enabled."""
        if self.config.get('Basic', {}).get('VisFrame') == 'on':
            try:
                data = json.dumps(self.frame_info, indent=4)
                with open(os.path.join(self.config['VisFrame']['LogInfoPath'], 'frame_info.json'), 'w+') as fw:
                    fw.write(data)
            except Exception:
                pass
            try:
                if getattr(self, 'frame_recorder', None) and self.frame_recorder.is_alive:
                    self.frame_recorder.interrupt()
            except Exception:
                pass
