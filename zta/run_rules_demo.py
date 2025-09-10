import os
import sys
import json

# Ensure package root is importable when running as a script
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from zta.scenario import ZTAScenario
from zta.env import ZTAEnv
from zta.zta_policy import ZTAPolicy


def seed_success(node, delay_norm: float = 0.0, overuse: float = 0.0, feedback: float = None):
    """Add one successful task result with given normalized delay and overuse; optionally add feedback."""
    if feedback is not None:
        node.add_feedback('seed', feedback)
    node.add_task_result(task_id='seed', success=True, delay=max(0.0, min(1.0, delay_norm)),
                         resource_usage={'overuse': max(0.0, min(1.0, overuse))}, criticality='low', timestamp=0)
    node.compute_final_trust()


def seed_failure(node, delay_norm: float = 1.0, overuse: float = 1.0, feedback: float = None):
    """Add one failed task result to depress performance/behavioral trust; optionally add feedback."""
    if feedback is not None:
        node.add_feedback('seed', feedback)
    node.add_task_result(task_id='seed-f', success=False, delay=max(0.0, min(1.0, delay_norm)),
                         resource_usage={'overuse': max(0.0, min(1.0, overuse))}, criticality='low', timestamp=0)
    node.compute_final_trust()


def seed_anomaly_oscillation(node):
    """Create oscillations in trust window to raise anomaly."""
    node.trust_sliding_window.clear()
    for v in [0.1, 0.9, 0.1, 0.9]:
        node.update_trust_sliding_window(v)
    node.compute_anomaly_index()


def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    scenario = ZTAScenario(config_file=os.path.join(current_dir, 'configs', 'zta_complex_topology.json'))
    with open(os.path.join(current_dir, 'configs', 'policy_rules.json'), 'r') as f:
        policy_cfg = json.load(f)
    env = ZTAEnv(scenario, policy=ZTAPolicy(policy_cfg))

    n0 = env.get_node('n0')
    n1 = env.get_node('n1')
    n2 = env.get_node('n2')
    n3 = env.get_node('n3')  # malicious
    n4 = env.get_node('n4')

    # Reset overrides to normal starting state
    env.set_overrides(system_load='normal', threat='normal')

    # Case 1: full_assignment (t>0.8, a<0.3, threat=normal)
    seed_success(n0, delay_norm=0.0, overuse=0.0, feedback=1.0)  # fused ~1.0
    env.assign_task({"id": 100, "size": 10, "cycles_per_bit": 10, "bitrate": 20, "src": "n0", "ddl": 20, "criticality": "low"})

    # Case 2: test_task_logging (0.6<=t<=0.8, load=low, criticality=high, threat=normal)
    env.set_overrides(system_load='low', threat='normal')
    seed_success(n1, delay_norm=0.9, overuse=0.0, feedback=1.0)  # fused ~0.73
    env.assign_task({"id": 101, "size": 10, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 20, "criticality": "high"})

    # Case 3: partial_assignment (0.5<=t<=0.7, a<0.3, load=high, criticality=high, threat=alert)
    env.set_overrides(system_load='high', threat='alert')
    seed_success(n2, delay_norm=0.7, overuse=0.0, feedback=0.5)  # fused ~0.64
    env.assign_task({"id": 102, "size": 10, "cycles_per_bit": 10, "bitrate": 20, "src": "n2", "ddl": 20, "criticality": "high"})

    # Case 4: full_assignment_monitoring (t>0.7, a<0.2, load=high, criticality=low, threat=normal)
    env.set_overrides(system_load='high', threat='normal')
    seed_success(n4, delay_norm=0.5, overuse=0.0, feedback=1.0)  # fused ~0.85
    env.assign_task({"id": 103, "size": 10, "cycles_per_bit": 10, "bitrate": 20, "src": "n4", "ddl": 20, "criticality": "low"})

    # Case 5: quarantine (t<0.5, a>0.5)
    env.set_overrides(system_load='normal', threat='normal')
    seed_failure(n3, delay_norm=1.0, overuse=1.0, feedback=0.2)  # fused low
    seed_anomaly_oscillation(n3)  # anomaly high
    env.assign_task({"id": 104, "size": 10, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 20, "criticality": "low"})

    # Run long enough for all to complete
    env.run(until=60)

    # Print summaries
    for name, node in scenario.get_nodes().items():
        try:
            print("\n---", name, "---\n" + node.node_info_str())
        except Exception:
            pass


if __name__ == '__main__':
    main()
