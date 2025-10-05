# import os
# import sys

# current_file_path = os.path.abspath(__file__)
# current_dir = os.path.dirname(current_file_path)
# parent_dir = os.path.dirname(current_dir)
# sys.path.insert(0, parent_dir)

# import json
# from zta.scenario import ZTAScenario
# from zta.env import ZTAEnv
# from zta.zta_policy import ZTAPolicy


# def main():
#     scenario = ZTAScenario(config_file=os.path.join(current_dir, 'configs', 'zta_complex_topology.json'))
#     with open(os.path.join(current_dir, 'configs', 'policy_rules.json'), 'r') as f:
#         policy_cfg = json.load(f)
#     env = ZTAEnv(scenario, policy=ZTAPolicy(policy_cfg))

#     # Example: submit a few dict-based tasks with varying criticality
#     # t0 = {"id": 0, "size": 20, "cycles_per_bit": 10, "bitrate": 20, "src": "n0", "ddl": 15, "criticality": "low"}
#     # t1 = {"id": 1, "size": 30, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 25, "criticality": "high"}
#     # t2 = {"id": 2, "size": 25, "cycles_per_bit": 10, "bitrate": 20, "src": "n2", "ddl": 20, "criticality": "low"}

#     # env.assign_task(t0)
#     # env.assign_task(t1)
#     # env.assign_task(t2)
#     # # Send a probe task to the malicious node to exercise detection
#     # t3 = {"id": 3, "size": 20, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 20, "criticality": "low"}
#     # env.process(t3, 'n3')

#     t0 = {"id": 0, "size": 20, "cycles_per_bit": 10, "bitrate": 20, "src": "n0", "ddl": 15, "criticality": "low"}
#     t1 = {"id": 1, "size": 30, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 25, "criticality": "high"}
#     t2 = {"id": 2, "size": 25, "cycles_per_bit": 10, "bitrate": 20, "src": "n2", "ddl": 20, "criticality": "low"}
#     t3 = {"id": 3, "size": 20, "cycles_per_bit": 10, "bitrate": 20, "src": "n1", "ddl": 20, "criticality": "low"}
#     # Assign to more destination nodes, e.g. n4, n5, n6, etc.
#     env.assign_task(t0)
#     env.assign_task(t1)
#     env.assign_task(t2)
#     env.process(t3, 'n4')

#     env.run(until=50)

#     # Print simple trust summaries
#     for name, node in scenario.get_nodes().items():
#         try:
#             info = node.node_info_str()
#             print("\n---", name, "---\n" + info)
#         except AttributeError:
#             pass

#     # no explicit close needed


# if __name__ == '__main__':
#     main()


# import os
# import sys

# current_file_path = os.path.abspath(__file__)
# current_dir = os.path.dirname(current_file_path)
# parent_dir = os.path.dirname(current_dir)
# sys.path.insert(0, parent_dir)

# import json
# from zta.scenario import ZTAScenario
# from zta.env import ZTAEnv
# from zta.zta_policy import ZTAPolicy

# def main():
#     current_file_path = os.path.abspath(__file__)
#     current_dir = os.path.dirname(current_file_path)
#     scenario = ZTAScenario(config_file=os.path.join(current_dir, 'configs', 'zta_complex_topology.json'))
#     with open(os.path.join(current_dir, 'configs', 'policy_rules.json'), 'r') as f:
#         policy_cfg = json.load(f)
#     env = ZTAEnv(scenario, policy=ZTAPolicy(policy_cfg))

#     num_nodes = len(scenario.get_nodes())
#     for i in range(num_nodes):
#         task = {
#             "id": i,
#             "size": 20 + i,
#             "cycles_per_bit": 10,
#             "bitrate": 20,
#             "src": f"n{i}",
#             "ddl": 15 + (i % 5) * 5,
#             "criticality": "high" if i % 2 == 0 else "low"
#         }
#         env.process(task)
#   # Forces the task to node n{i}

#     env.run(until=50)

#     for name, node in scenario.get_nodes().items():
#         try:
#             info = node.node_info_str()
#             print("\n---", name, "---\n" + info)
#         except AttributeError:
#             pass

# if __name__ == '__main__':
#     main()

import os
import sys

# (Keep your sys.path setup as is)
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

import json
from zta.scenario import ZTAScenario
from zta.env import ZTAEnv
from zta.zta_policy import ZTAPolicy

def main():
    current_file_path = os.path.abspath(__file__)
    current_dir = os.path.dirname(current_file_path)
    scenario = ZTAScenario(config_file=os.path.join(current_dir, 'configs', 'zta_complex_topology.json'))
    with open(os.path.join(current_dir, 'configs', 'policy_rules.json'), 'r') as f:
        policy_cfg = json.load(f)
    env = ZTAEnv(scenario, policy=ZTAPolicy(policy_cfg))

    num_nodes = len(scenario.get_nodes())

    # --- 1. Warm-Up Phase ---
    # Assign one initial task to each node to build a baseline trust score.
    print("--- STARTING WARM-UP PHASE ---")
    for i in range(num_nodes):
        task = {
            "id": f"warmup_{i}",
            "size": 20,
            "cycles_per_bit": 10,
            "src": f"n{i}",
            "ddl": 20,
            "criticality": "low"
        }
        # Force-assign the task to a specific node
        env.process(task, f"n{i}")
    
    # Run the simulation long enough for warm-up tasks to complete
    env.run(until=50)
    print("--- WARM-UP COMPLETE ---")
    
    # --- 2. Main Simulation Phase ---
    # Now, let the policy make all the decisions.
    print("--- STARTING MAIN SIMULATION ---")
    for i in range(num_nodes * 2): # Run more tasks
        task = {
            "id": i,
            "size": 20 + i,
            "cycles_per_bit": 10,
            "bitrate": 20,
            "src": f"n{i % num_nodes}",
            "ddl": 15 + (i % 5) * 5,
            "criticality": "high" if i % 2 == 0 else "low"
        }
        # Let the policy decide where the task goes
        env.process(task)
        
    # Run the simulation for the main phase
    env.run(until=200)

    # --- 3. Print Final Results ---
    for name, node in scenario.get_nodes().items():
        try:
            info = node.node_info_str()
            print("\n---", name, "---\n" + info)
        except AttributeError:
            pass

if __name__ == '__main__':
    main()