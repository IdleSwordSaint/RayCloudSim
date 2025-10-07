import os
import sys
import json
import csv
import random

# Add parent directory to path to import ZTA modules
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from zta.scenario import ZTAScenario
from zta.env import ZTAEnv
from zta.zta_policy import ZTAPolicy

def run_real_workload_demo(topology_file, workload_file):
    """
    Runs the ZTA simulation using the Milan topology and workload trace.
    """
    # --- Standard Setup ---
    # The ZTAScenario class should be able to read your new topology JSON directly
    scenario = ZTAScenario(config_file=os.path.join(current_dir, 'configs', topology_file))
    with open(os.path.join(current_dir, 'configs', 'policy_rules.json'), 'r') as f:
        policy_cfg = json.load(f)
    env = ZTAEnv(scenario, policy=ZTAPolicy(policy_cfg))

    # --- Read Workload from CSV ---
    with open(workload_file, 'r') as f:
        reader = csv.DictReader(f)
        tasks_from_csv = list(reader)

    # --- Simulation Loop ---
    events_by_time = {}
    for i, row in enumerate(tasks_from_csv):
        # --- Column mapping for your new workload file ---
        try:
            timestamp = float(row['GenerationTime'])
            task = {
                "id": row['TaskID'],
                "size": float(row['TaskSize']),
                "cycles_per_bit": float(row['CyclesPerBit']),
                "bitrate": float(row.get('TransBitRate', 20)), # Use default if not present
                "ddl": float(row['DDL']),
                "src": row['SrcName'],
                "criticality": random.choice(['low', 'high']) # Assign random criticality
            }
        except (ValueError, TypeError, KeyError) as e:
            print(f"Warning: Skipping row {i+1} due to data error: {e}")
            continue
        
        if timestamp not in events_by_time:
            events_by_time[timestamp] = []
        events_by_time[timestamp].append(task)

    # Process events in chronological order
    print(f"Starting simulation with {len(tasks_from_csv)} tasks from workload file...")
    for timestamp in sorted(events_by_time.keys()):
        if timestamp > env.now:
            env.run(until=timestamp)
        
        for task in events_by_time[timestamp]:
            # Let the ZT policy decide the destination for every task
            env.process(task)
    
    # After all events are submitted, run the simulation for a while longer to finish
    last_timestamp = sorted(events_by_time.keys())[-1]
    env.run(until=last_timestamp + 500)

    # --- Final Results ---
    print("\n--- SIMULATION COMPLETE: FINAL NODE STATES ---")
    for name, node in scenario.get_nodes().items():
        try:
            info = node.node_info_str()
            print("\n---", name, "---\n" + info)
        except AttributeError:
            pass

    print("\n--- POLICY ACTION COUNTS ---")
    if not env.action_counts:
        print("No actions were recorded.")
    else:
        for action, count in sorted(env.action_counts.items()):
            print(f"- {action}: {count}")

if __name__ == '__main__':
    TOPOLOGY_FILENAME = 'milan_topology.json'
    WORKLOAD_FILENAME = 'milan_workload.csv'
    
    if not os.path.exists(f'configs/{TOPOLOGY_FILENAME}'):
        print(f"Error: Topology file 'configs/{TOPOLOGY_FILENAME}' not found.")
    elif not os.path.exists(WORKLOAD_FILENAME):
        print(f"Error: Workload file '{WORKLOAD_FILENAME}' not found.")
    else:
        run_real_workload_demo(TOPOLOGY_FILENAME, WORKLOAD_FILENAME)