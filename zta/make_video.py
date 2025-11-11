"""
Build a simple topology video from recorded frames.

Usage (from repo root):
  . .venv/bin/activate
  python zta/make_video.py

Requires that you have already run a demo (e.g., run_complex_demo.py),
which writes `zta/logs/vis_zta/frame_info.json` when it finishes.
"""
import os
import sys

# Ensure repo root is on sys.path so `import zta.*` works when run via `python zta/make_video.py`
here = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.dirname(here)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from zta.scenario import ZTAScenario
from zta.env import ZTAEnv
from zta.vis import vis_frame2video


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    frame_info = os.path.join(here, 'logs', 'vis_zta', 'frame_info.json')
    if not os.path.exists(frame_info):
        print('frame_info.json not found. Run a demo first (e.g., python run_complex_demo.py).')
        return

    scenario = ZTAScenario(config_file=os.path.join(here, 'configs', 'zta_complex_topology.json'))
    env = ZTAEnv(scenario)  # loads zta/configs/env_config.json by default
    # Ensure paths are absolute to this zta folder
    env.config['VisFrame']['LogInfoPath'] = os.path.join(here, 'logs', 'vis_zta')
    env.config['VisFrame']['LogFramesPath'] = os.path.join(here, 'logs', 'vis_zta', 'frames')
    vis_frame2video(env)
    print(f"Video saved to {os.path.join(here, 'logs', 'vis_zta', 'out.avi')}")


if __name__ == '__main__':
    main()
