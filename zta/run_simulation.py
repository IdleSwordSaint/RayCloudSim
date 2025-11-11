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
from zta.vis.plots import render_zta_summary
from zta.vis import vis_frame2video


def _plot_trust_timeseries(env: ZTAEnv, scenario: ZTAScenario, save_path: str) -> None:
    """Plot trust scores of all nodes over time.

    Uses per-tick `final_trust` values recorded by the env's frame recorder.
    Colors: red lines = malicious nodes; blue lines = normal nodes.
    """
    try:
        os.environ.setdefault('MPLBACKEND', 'Agg')
        import matplotlib.pyplot as plt
    except Exception:
        return

    # Prefer in-memory frame info if available and non-empty
    frame_info = getattr(env, 'frame_info', {}) or {}
    if not frame_info:
        # Best-effort fallback: try reading the flushed JSON
        try:
            info_path = os.path.join(env.config['VisFrame']['LogInfoPath'], 'frame_info.json')
            if os.path.exists(info_path):
                with open(info_path, 'r') as f:
                    frame_info = json.load(f)
                    # Keys may be strings from JSON; convert to floats when possible
                    frame_info = {float(k): v for k, v in frame_info.items()}
        except Exception:
            frame_info = {}

    if not frame_info:
        # Nothing to plot
        return

    times = sorted(frame_info.keys())
    nodes = scenario.get_nodes()

    plt.figure(figsize=(10, 5))
    plt.title('Trust Scores Over Time (final_trust)')
    for name, node in nodes.items():
        # Determine color by malicious flag
        is_mal = False
        try:
            is_mal = bool(getattr(node, 'malicious_type', None))
        except Exception:
            is_mal = False
        color = '#FA7F6F' if is_mal else '#82B0D2'

        series = []
        for t in times:
            v = frame_info[t].get('node', {}).get(name, None)
            # Ensure numeric; skip if missing
            try:
                series.append(float(v) if v is not None else float('nan'))
            except Exception:
                series.append(float('nan'))

        plt.plot(times, series, color=color, linewidth=1.5, alpha=0.9)

    plt.xlabel('time')
    plt.ylabel('final_trust')
    plt.ylim(0, 1.05)
    plt.tight_layout()
    try:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path)
    finally:
        plt.close()

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

    # --- Visualization + Video + Trust Timeseries ---
    # Flush any frame info for optional video building
    try:
        env.close()
    except Exception:
        pass

    out_dir = os.path.join(current_dir, 'logs')
    try:
        outputs = render_zta_summary(env, scenario, save_dir=out_dir)
        print("\n--- SAVED PLOTS ---")
        for k, v in outputs.items():
            print(f"- {k}: {v}")
    except Exception as e:
        print(f"Visualization error: {e}")

    # Trust scores over time (red=malicious, blue=normal)
    try:
        ts_path = os.path.join(out_dir, 'trust_over_time.png')
        _plot_trust_timeseries(env, scenario, ts_path)
        if os.path.exists(ts_path):
            print(f"- trust_timeseries: {ts_path}")
    except Exception:
        pass

    # Try to build a video automatically
    try:
        os.environ.setdefault('MPLBACKEND', 'Agg')
        # Ensure fresh frames per run
        frames_dir = os.path.join(current_dir, 'logs', 'vis_zta', 'frames')
        try:
            import glob
            for p in glob.glob(os.path.join(frames_dir, '*.png')):
                os.remove(p)
        except Exception:
            pass
        vis_frame2video(env)
        video_path = os.path.join(current_dir, 'logs', 'vis_zta', 'out.avi')
        print(f"\n--- VIDEO BUILT ---\n- video: {video_path}")
    except Exception as video_err:
        # Fallback: attempt using the repo root venv if available
        root_python = os.path.join(parent_dir, '.venv', 'bin', 'python')
        make_script = os.path.join(current_dir, 'make_video.py')
        try:
            if os.path.exists(root_python) and os.path.exists(make_script):
                print("Video build failed in local env; retrying via repo venv...")
                import subprocess
                subprocess.run([root_python, make_script], check=True)
                print(f"\n--- VIDEO BUILT (fallback) ---\n- video: {os.path.join(current_dir, 'logs', 'vis_zta', 'out.avi')}")
            else:
                raise RuntimeError(str(video_err))
        except Exception:
            print("\nVideo build skipped. To build manually, run:\n  . .venv/bin/activate\n  python zta/make_video.py")

if __name__ == '__main__':
    TOPOLOGY_FILENAME = 'milan_topology.json'
    WORKLOAD_FILENAME = 'milan_workload.csv'
    
    if not os.path.exists(f'configs/{TOPOLOGY_FILENAME}'):
        print(f"Error: Topology file 'configs/{TOPOLOGY_FILENAME}' not found.")
    elif not os.path.exists(WORKLOAD_FILENAME):
        print(f"Error: Workload file '{WORKLOAD_FILENAME}' not found.")
    else:
        run_real_workload_demo(TOPOLOGY_FILENAME, WORKLOAD_FILENAME)
