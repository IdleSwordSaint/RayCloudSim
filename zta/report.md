# Zero Trust Scenario in RayCloudSim — Project Report

Author: RayCloudSim ZTA Team  
Date: 2025-09-10

## 1) Purpose (Plain English)
- We added a Zero Trust Architecture (ZTA) scenario to RayCloudSim so you can simulate how tasks are assigned to compute nodes using trust and anomaly signals, not just performance.
- The system chooses actions (full assignment, test + logging, partial, monitoring, or quarantine) based on a simple rule matrix inspired by the paper you shared.
- The demo shows how trust is calculated, how anomalies reduce final trust, and how the rule matrix routes work to good nodes and limits risky ones.

## 2) What We Built
- ZTA Nodes with trust/anomaly metrics.
- A rule-driven ZTA Policy that maps final trust + anomaly + system state → action.
- A ZTA Environment that prints the state and drives SimPy processes (transmit + execute).
- Example topologies and demos (simple and complex) to exercise all actions in the rule table.

## 3) Where the Pieces Live (Key Files)
- `zta/zta_node.py`: ZTA node with trust window, anomaly index, and final trust.
- `zta/zta_policy.py`: Rule-based policy. Reads rules from JSON and returns (node, action).
- `zta/env.py`: Friend-authored SimPy environment (corrected) orchestrating assignment and execution.
- `zta/scenario.py`: Scenario that creates ZTA-aware nodes/links from JSON.
- `zta/link.py`: Link with optional ZTA overhead knobs (encryption/auth latency).
- `zta/task.py`: Task with ZTA attributes (criticality, sensitivity, crypto/auth flags).
- `zta/configs/policy_rules.json`: Your assignment matrix in JSON.
- `zta/configs/zta_topology.json`: Small, linear 4-node example (incl. one malicious).
- `zta/configs/zta_complex_topology.json`: Larger 10-node graph with two malicious nodes.
- `zta/run_demo.py`: Basic demo using the complex topology.
- `zta/run_rules_demo.py`: Demo that forces each row of the rule matrix to trigger.

## 4) How It Works (Flow)
1. A task arrives with metadata (size, ddl, criticality, bitrate, source).  
2. The environment asks the policy to select a destination and action based on:  
   - Node final trust (fused trust penalized by anomaly)  
   - System load (low/normal/high)  
   - Threat level (normal/alert)  
   - Task criticality (low/high)  
3. The environment prints a state line like:  
   `state | load=high threat=normal criticality=low action=full_assignment_monitoring dst=n4 t_final=0.86 anomaly=0.03`  
4. The task transmits (shortest path) and executes. On completion, the node updates trust and anomaly.

## 5) Trust, Anomaly, Final Trust (Summary)
- Performance trust: successes / total.
- Feedback trust: robust mean of peer feedback; defaults to 0.5 when none exists (uninformative prior).
- Behavioral trust: 1 − (normalized delay + overuse), clipped to [0, 1].  
  - Delay normalization uses `ddl` if present; else `exe_time / (1 + exe_time)`.
- Fused trust: weighted sum (0.4 perf + 0.3 feedback + 0.3 behavioral).  
  - We chose a sum to avoid geometric “zero‑collapse.”
- Anomaly index: softmax‑weighted combination of oscillation, variance, and change‑points on the sliding trust window.
- Final trust: `t_final = fused / (1 + anomaly)`.

If the paper specifies different formulas/weights, we can switch them easily.

## 6) Rule-Based Assignment Matrix (from your figure)
Encoded in `zta/configs/policy_rules.json`:
- Full Assignment: `t_final > 0.8`, `anomaly < 0.3`, `threat = normal`.
- Test Task + Logging: `0.6–0.8`, `load = low`, `criticality = high`, `threat = normal`.
- Quarantine: `t_final < 0.5`, `anomaly > 0.5`. (other fields: Any)
- Partial Assignment: `0.5–0.7`, `anomaly < 0.3`, `load = high`, `criticality = high`, `threat = alert`.
- Full Assignment + Monitoring: `t_final > 0.7`, `anomaly < 0.2`, `load = high`, `criticality = low`, `threat = normal`.

The policy selects actions strictly from this JSON (priority is configurable).

## 7) How to Run
- Install deps once:  
  `pip install -r requirements.txt -r zta/requirements.txt`
- Basic demo:  
  `python zta/run_demo.py`
- All-rule demo (triggers every action row):  
  `python zta/run_rules_demo.py`
- Complex timeline demo:  
  `cd zta && . .venv/bin/activate && python run_complex_demo.py`
  - Saves plots to `zta/logs/`:
    - `plots_action_counts.png`
    - `plots_node_metrics.png`
    - `topology_trust.png`
  - Also records per-tick frames to `zta/logs/vis_zta/frame_info.json`.
    Build a video after the run: `python zta/make_video.py`

You’ll see the “state” lines during assignment and a trust/anomaly summary per node at the end.

## 8) What the Logs Mean
- `Task generated / Processing / Accomplished`: execution lifecycle events.  
- `state | ... action=... dst=... t_final=... anomaly=...`: chosen action and the selected node’s final trust/anomaly at decision time.  
- Per‑node printouts show current window, fused trust, and anomaly for inspection.

## 9) Current Problems We’re Addressing
- Early cold‑start: with no feedback/behavioral history, many nodes tie.  
  - Mitigation: use a neutral feedback prior (0.5), add test‑tasks, and prefer local or most‑idle nodes when all trust≈0.
- Anomaly sensitivity: thresholds may need tuning per workload.  
  - We expose parameters and JSON rules; adjust to your study.
- Congestion/buffer errors in tiny topologies: can mask ZTA behavior.  
  - We increased bandwidths/buffers in examples and staggered probes.
- Exact paper alignment: if your PDF has precise formulas/weights, we will encode them (now it’s configurable).

## 10) Assumptions & Config Knobs
- Feedback baseline of 0.5 for cold‑start neutrality (configurable if you want conservative 0.3 or optimistic 0.6).
- Fusion by weighted sum (0.4/0.3/0.3).  
- Threat: ‘alert’ when any node’s anomaly>0.7; overrideable in demos.
- Rule matrix loads from `policy_rules.json` so you can tweak thresholds without code changes.

## 11) How the Code is Wired
- The environment (`zta/env.py`) calls the policy (`zta/zta_policy.py`) for each task to get `(node_idx, action)`.  
- The policy computes node scores using each node’s `compute_final_trust()` and `anomaly_index`.  
- The scenario (`zta/scenario.py`) constructs ZTA nodes and links from JSON, exposing `node_id2name` indexing used by the policy.

## 12) Extending/Next Steps
- Replace the fusion weights with those in your PDF (or geometric fusion if specified).
- Add richer feedback mechanisms (e.g., signed reports, filtering) instead of a neutral prior.
- Model encryption/auth latency directly in transmission using `zta/link.py` overheads.
- Add periodic test‑task probes to under‑observed nodes automatically.
- Add plots (trust over time, anomaly spikes, action counts) for results sections.

## 13) Repro & Export to PDF
- This report is saved at `zta/report.md`.  
- To export as PDF:
  - VS Code: Open file → “Print…” → Save as PDF (or use a Markdown PDF extension).  
  - Or, if you have Pandoc/LaTeX:  
    `pandoc zta/report.md -o zta/report.pdf`
