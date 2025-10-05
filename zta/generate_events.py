# # File: generate_events.py (Corrected)
# import csv

# def generate_complex_scenario():
#     """
#     Generates a CSV file with a timeline of events designed to trigger
#     various Zero Trust policy actions.
#     """
#     header = [
#         'timestamp', 'event_type', 'event_target', 'task_id', 'task_size',
#         'cycles_per_bit', 'ddl', 'criticality', 'src_node', 'force_dst_node'
#     ]

#     events = []

#     # --- Phase 1: Warm-Up (Timestamp 0) ---
#     # Goal: Establish a HEALTHY baseline trust for all nodes.
#     # MODIFIED: Task size is now 5, making it easy to complete well within the DDL of 20.
#     for i in range(10):
#         events.append([
#             0, 'TASK_SUBMIT', '', f'warmup_{i}', 5, 10, 20, 'low', f'n{i}', f'n{i}'
#         ])

#     # --- Phase 2: Normal Operations (Timestamps 50-70) ---
#     # Goal: Let the policy work under normal, low-threat conditions.
#     for i in range(3):
#         events.append([
#             50 + (i * 10), 'TASK_SUBMIT', '', f'normal_{i}', 25, 10, 25, 'high', f'n{i}', ''
#         ])

#     # --- Phase 3: Introduce a Threat (Timestamp 80) ---
#     # Goal: Make a node malicious to increase its anomaly score over time.
#     events.append([80, 'MAKE_MALICIOUS', 'n3', '', '', '', '', '', '', ''])
    
#     # Submit tasks that the malicious node might pick up, causing failures.
#     for i in range(3):
#          events.append([
#             85 + (i * 10), 'TASK_SUBMIT', '', f'bait_{i}', 30, 10, 15, 'high', f'n{i+1}', ''
#         ])

#     # --- Phase 4: High Load & High Threat (Timestamp 120) ---
#     # Goal: Trigger "Partial Assignment" by creating a high-load, high-threat state.
#     for i in range(6):
#         events.append([
#             120, 'TASK_SUBMIT', '', f'burst_{i}', 50, 10, 40, 'low', f'n{i+4}', ''
#         ])
    
#     events.append([
#         121, 'TASK_SUBMIT', '', 'critical_task_1', 35, 10, 30, 'high', 'n0', ''
#     ])

#     # --- Phase 5: Quarantine (Timestamp 150) ---
#     # Goal: Trigger "Quarantine" after the malicious node has failed repeatedly.
#     events.append([
#         150, 'TASK_SUBMIT', '', 'final_task', 20, 10, 20, 'low', 'n1', ''
#     ])


#     with open('complex_scenario_events.csv', 'w', newline='') as f:
#         writer = csv.writer(f)
#         writer.writerow(header)
#         writer.writerows(events)

#     print("complex_scenario_events.csv generated successfully.")


# if __name__ == '__main__':
#     generate_complex_scenario()

# File: generate_events.py (Updated for ~100 tasks and Partial Assignment)
import csv

def generate_complex_scenario():
    """
    Generates a CSV file with over 100 events designed to trigger
    a full range of Zero Trust policy actions, including Partial Assignment.
    """
    header = [
        'timestamp', 'event_type', 'event_target', 'task_id', 'task_size',
        'cycles_per_bit', 'ddl', 'criticality', 'src_node', 'force_dst_node'
    ]

    events = []
    task_counter = 0

    # --- Phase 1: Warm-Up (10 Tasks) ---
    # Goal: Establish a healthy baseline trust for all 10 nodes.
    for i in range(10):
        events.append([
            0, 'TASK_SUBMIT', '', f'warmup_{i}', 5, 10, 20, 'low', f'n{i}', f'n{i}'
        ])
        task_counter += 1

    # --- Phase 2: Normal Operations (30 Tasks) ---
    # Goal: Run the system under normal conditions to see trust scores evolve.
    for i in range(30):
        events.append([
            50 + (i * 5), 'TASK_SUBMIT', '', f'normal_{i}', 25, 10, 30, 'high', f'n{i%10}', ''
        ])
        task_counter += 1

    # --- Phase 3: Induce High Threat (20 Tasks) ---
    # Goal: Make a node malicious and give it tasks to fail, raising the Threat Level to 'alert'.
    malicious_node_turn_time = 200
    events.append([malicious_node_turn_time, 'MAKE_MALICIOUS', 'n3', '', '', '', '', '', '', ''])
    
    # Submit a wave of "bait" tasks after n3 becomes malicious.
    # The policy will likely assign some to n3 before its trust collapses.
    for i in range(20):
        events.append([
            malicious_node_turn_time + 5 + (i * 5), 'TASK_SUBMIT', '', f'bait_{i}', 30, 10, 15, 'high', f'n{i%10}', ''
        ])
        task_counter += 1

    # --- Phase 4: Induce High Load (30 Tasks) ---
    # Goal: Create a "burst" of simultaneous tasks to push System Load to 'high'.
    burst_time = 300
    for i in range(30):
        events.append([
            burst_time, 'TASK_SUBMIT', '', f'burst_{i}', 60, 10, 50, 'low', f'n{i%10}', ''
        ])
        task_counter += 1

    # --- Phase 5: The Trigger for Partial Assignment (1 Task) ---
    # Goal: Submit a high-criticality task when load is 'high' AND threat is 'alert'.
    trigger_time = 301
    events.append([
        trigger_time, 'TASK_SUBMIT', '', 'TRIGGER_TASK_PARTIAL', 40, 10, 35, 'high', 'n0', ''
    ])
    task_counter += 1
    
    # --- Phase 6: Cool-down and Quarantine (10 Tasks) ---
    # Goal: Allow the system to stabilize and eventually quarantine the bad node.
    for i in range(10):
        events.append([
            350 + (i * 10), 'TASK_SUBMIT', '', f'cooldown_{i}', 20, 10, 25, 'low', f'n{i%10}', ''
        ])
        task_counter += 1


    with open('complex_scenario_events.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(events)

    print(f"complex_scenario_events.csv generated successfully with {task_counter} tasks.")
    print("This scenario is designed to trigger 'Partial Assignment' around t=301.")


if __name__ == '__main__':
    generate_complex_scenario()