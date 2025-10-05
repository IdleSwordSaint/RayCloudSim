# File: run_complex_demo.py (Corrected)
import os
import sys
import json
import csv

# Add parent directory to path to import ZTA modules
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from zta.scenario import ZTAScenario
from zta.env import ZTAEnv
from zta.zta_policy import ZTAPolicy

def run_demo_from_csv(csv_filepath):
    """
    Runs the ZTA simulation based on a timeline of events from a CSV file.
    """
    # --- Standard Setup ---
    scenario = ZTAScenario(config_file=os.path.join(current_dir, 'configs', 'zta_complex_topology.json'))
    with open(os.path.join(current_dir, 'configs', 'policy_rules.json'), 'r') as f:
        policy_cfg = json.load(f)
    env = ZTAEnv(scenario, policy=ZTAPolicy(policy_cfg))

    # --- Read Events from CSV ---
    with open(csv_filepath, 'r') as f:
        reader = csv.DictReader(f)
        events = list(reader)

    # Convert numeric fields from string
    for event in events:
        for field in ['timestamp', 'task_size', 'cycles_per_bit', 'ddl']:
            if event.get(field) and event[field]:
                event[field] = float(event[field])

    # --- Corrected Simulation Loop ---
    events_by_time = {}
    for event in events:
        ts = event['timestamp']
        if ts not in events_by_time:
            events_by_time[ts] = []
        events_by_time[ts].append(event)

    for timestamp in sorted(events_by_time.keys()):
        # --- ADDED THIS CHECK ---
        # Only run the simulation if the next event is in the future.
        if timestamp > env.now:
            env.run(until=timestamp)
        
        # Process all events for the current timestamp
        for event in events_by_time[timestamp]:
            if event['event_type'] == 'MAKE_MALICIOUS':
                node_name = event['event_target']
                node = env.get_node(node_name)
                if node:
                    node.set_malicious_type(1)
                    print(f"INFO @ t={env.now:.2f}: Node {node_name} is now malicious.")
            
            elif event['event_type'] == 'TASK_SUBMIT':
                task = {
                    "id": event['task_id'],
                    "size": event['task_size'],
                    "cycles_per_bit": event['cycles_per_bit'],
                    "ddl": event['ddl'],
                    "criticality": event['criticality'],
                    "src": event['src_node']
                }

                dst_node = event.get('force_dst_node')
                if dst_node:
                    env.process(task, dst_node)
                else:
                    env.process(task)
    
    last_timestamp = sorted(events_by_time.keys())[-1]
    env.run(until=last_timestamp + 200)

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
    event_file = 'complex_scenario_events.csv'
    if not os.path.exists(event_file):
        print(f"{event_file} not found. Please run generate_events.py first.")
    else:
        run_demo_from_csv(event_file)