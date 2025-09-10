import os
import sys

current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

import json
from zta.scenario import ZTAScenario
from zta.env import ZTAEnv
from zta.zta_policy import ZTAPolicy


def main():
    scenario = ZTAScenario(config_file=os.path.join(current_dir, 'configs', 'zta_complex_topology.json'))
    with open(os.path.join(current_dir, 'configs', 'policy_rules.json'), 'r') as f:
        policy_cfg = json.load(f)
    env = ZTAEnv(scenario, policy=ZTAPolicy(policy_cfg))

    # Example: submit a few dict-based tasks with varying criticality
    t0 = {"id": 0, "size": 20, "cycles_per_bit": 10, "bitrate": 20, "src": "n0", "ddl": 15, "criticality": "low"}
    t1 = {"id": 1, "size": 30, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 25, "criticality": "high"}
    t2 = {"id": 2, "size": 25, "cycles_per_bit": 10, "bitrate": 20, "src": "n2", "ddl": 20, "criticality": "low"}

    env.assign_task(t0)
    env.assign_task(t1)
    env.assign_task(t2)
    # Send a probe task to the malicious node to exercise detection
    t3 = {"id": 3, "size": 20, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 20, "criticality": "low"}
    env.process(t3, 'n3')

    env.run(until=50)

    # Print simple trust summaries
    for name, node in scenario.get_nodes().items():
        try:
            info = node.node_info_str()
            print("\n---", name, "---\n" + info)
        except AttributeError:
            pass

    # no explicit close needed


if __name__ == '__main__':
    main()
