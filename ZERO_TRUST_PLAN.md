# Zero Trust Architecture (ZTA) for Fog Computing Simulator

## Overview
This document provides a comprehensive plan and implementation guide for integrating a Zero Trust Architecture (ZTA) into a fog computing simulator. The approach follows the three core ZTA pillars:
- **Verify Explicitly**
- **Use Least Privilege Access**
- **Assume Breach**

It covers all required components, simulation requirements, file modifications, and implementation details, including a code skeleton for the `ZTAEngine` class. The focus is on a fog environment with distributed compute units, ensuring continuous trust evaluation, minimal privilege assignment, and robust security against internal threats.

---

## Component Checklist and Status
The following components are required to implement ZTA in the simulator (all currently pending):
- **Behavioral Trust Logic**: Logic to assess node behavior.
- **Fused and Final Trust Scores**: Compute Tperf (performance), Tfb (feedback), Tbeh (behavioral), fused (Tfused), and final (Tfinal) trust scores.
- **Anomaly Detection (Sliding Window)**: Use a sliding window to detect behavioral anomalies.
- **System Context Simulation**: Simulate load, threat level, and task criticality.
- **Rule-Based ZTA Engine**: Develop a policy engine for ZTA decisions.
- **ZTA Engine Integration**: Integrate the ZTA engine into the task scheduler.
- **Adversarial Node Simulation**: Simulate malicious nodes for testing.
- **Logging for Analysis**: Log trust scores, decisions, and anomalies.

---

## Simulation Components
To simulate ZTA in a fog environment, the following components are required:
- **Fog Nodes**: Distributed compute units, which can be mobile, malicious, or normal.
- **Tasks**: Workload units assigned by the orchestrator, tagged with criticality (LOW, MEDIUM, HIGH).
- **Trust Engine**: Calculates trust scores:
    - **Performance (Tperf)**: Based on node metrics (e.g., CPU usage, task completion).
    - **Feedback (Tfb)**: Based on external feedback or peer reviews.
    - **Behavioral (Tbeh)**: Based on node behavior patterns.
    - **Fused (Tfused)**: Combined score from Tperf, Tfb, and Tbeh.
    - **Anomaly Index**: Detects irregularities in node behavior.
- **Policy Engine**: Applies ZTA rules to accept, deny, monitor, or quarantine nodes.
- **Environment**: Contextual factors including system load, task criticality, threat level, and time (env.now).

---

## Modified Files
The following files are updated to support ZTA implementation:
- **node.py**: Defines node properties (e.g., TrustNode, MaliciousNode, access_level, trust window, location as LocX, LocY).
- **env.py**: Includes `env.now` for time-based context and system load simulation.
- **ZAM.py**: Includes test scenarios and configurations for adversarial node simulation and policy testing.
- **Test Scenarios and Configs**: Added to ZAM.py to test ZTA behavior under various conditions (e.g., malicious nodes, high load).

*Note: Only these files are modified, ensuring a focused update scope.*

---

## ZTA Pillars Implementation

### 1. Verify Explicitly
Authenticate and authorize each node for every task assignment using multiple data points to ensure no trust assumptions persist.

**Data Points:**
- Identity: Node ID or Name
- Location: Node coordinates (LocX, LocY)
- Device Health: CPU load, buffer size, failed tasks, overheating flag
- Time of Day: Use `env.now` for scheduling biases (e.g., risky hours)
- Behavior Anomalies: Anomaly index from sliding window of trust scores

**Implementation:**
- In `ZTAEngine`, pull node properties at the moment of decision.
- Use conditions or scoring to influence task assignment.

**Pseudo-Code Example:**
```python
if node.anomaly_index > 0.6 or node.health_score < 0.4 or node.location in restricted_zone:
    return "quarantine"
elif env.now in [22, 6] and task.criticality == "HIGH":  # Risky hours
    return "assign_test_task"
else:
    return "assign"
```
- **Outcome:** Trust is re-evaluated for every task assignment, ensuring explicit verification.

### 2. Use Least Privilege Access
Assign nodes the minimum access required for tasks to limit lateral movement during attacks.

**Implementation:**
- **Task Tagging:** Add a `TaskCriticality` column (LOW, MEDIUM, HIGH) to the task dataset.
- **Node Permissions:** Define `access_level` (e.g., LOW_ONLY, LOW_MEDIUM) in node classes.
- **ZTA Engine Logic:** Block high-criticality tasks from low-trust nodes.
    - Tfinal > 0.75: Assign any task
    - Tfinal > 0.5: Assign low-criticality tasks with monitoring
    - Tfinal ≤ 0.5: Monitor or quarantine

**Pseudo-Code Example:**
```python
if node.Tfinal > 0.75:
    allow_full_assignment()
elif node.Tfinal > 0.5:
    if task.criticality == "LOW":
        assign_with_monitoring()
    else:
        return "monitor"
else:
    return "quarantine"
```
- **Outcome:** Enforces least privilege by matching task criticality to node trust levels.

### 3. Assume Breach
Design the system assuming attackers are already inside, using microsegmentation, quarantine, decoy tasks, and comprehensive logging.

**Techniques:**
- Microsegmentation: Restrict tasks or communication to trusted nodes
- Quarantine: Prevent task assignment to malicious or suspicious nodes
- Decoy Tasks: Assign fake tasks to test node behavior
- Logging: Record all assignment decisions, trust scores, and anomalies

**Implementation:**
- In `ZTAEngine` or TaskScheduler:
    - Define network zones or node groups to enforce microsegmentation
    - Track node history for trust drops or feedback inconsistencies
    - Inject decoy tasks for anomaly probing

**Pseudo-Code Example:**
```python
if node in zone_A and trust_drop_detected:
    quarantine_node(node)
if node.type == "MaliciousNode":
    inject_decoy_task(node)
log_decision(node, task, action)
```
- **Outcome:** Limits blast radius and detects internal threats through proactive measures.

---

## Continuous Trust Loop Architecture
The simulation operates in a continuous cycle for each task:
1. Task Arrives: A new task is received for assignment.
2. Evaluate Node Trust: Compute Tfinal and anomaly index for each node.
3. Update Sliding Window: Append current trust score to node’s trust window.
4. Recalculate Anomaly Index: Analyze oscillation, variance, and change points.
5. Apply ZTA Policy: Decide to assign, test, monitor, or quarantine.
6. Node Executes Task: Node processes the assigned task.
7. Update Trust: Adjust trust scores based on task outcome.
8. Repeat: Re-evaluate for the next task.

---

## Decision Engine Workflow
The ZTA decision engine processes access requests as follows:
- **Access Request:** A device or user requests to perform an action (e.g., task execution).
- **Context Gathering:**
    - Identity and role
    - Device posture (health metrics)
    - Location (LocX, LocY)
    - Workload context (task criticality)
    - Risk score (current and historical)
- **Policy Engine Evaluation:**
    - Apply access control rules based on trust and context
    - Use behavioral or ML-based models to score risk
- **Access Decision:**
    - Grant: Assign task normally
    - Deny: Block task assignment
    - Step-Up Auth: Require additional verification
    - Monitor: Assign task with logging
    - Quarantine: Isolate node
- **Implementation Options:**
    - Python dictionaries for rule storage
    - Decision trees for complex logic
    - Fuzzy logic for flexible scoring
    - Simple if-else chains for discrete simulation

---

## Implementation Details

### Trust Scores
- Compute Tperf, Tfb, Tbeh based on node metrics, feedback, and behavior
- Combine into Tfused = (Tperf + Tfb + Tbeh) / 3
- Adjust for anomalies: Tfinal = Tfused / (1 + anomaly_index)

### Anomaly Detection
- Use a sliding window (size=5) to track trust history:
```python
node.trust_window.append(current_tfused)
if len(node.trust_window) > 5:
    node.trust_window.pop(0)
osc = compute_oscillation(node.trust_window)
var = compute_variance(node.trust_window)
cp = detect_change_points(node.trust_window)
anomaly_index = weighted_score(osc, var, cp)
```

### System Context
- Incorporate load, threat level, task type, and time (env.now) in ZTAEngine

### Policy Rules
- Use Python dictionaries, decision trees, or if-else chains
- Example rule matrix:
    - Trust | Task Type | Action
    - High  | Low       | Assign
    - Medium| High      | Assign with monitoring
    - Low   | Any       | Quarantine or test

### Custom FogNode
- Start with a custom FogNode class in node.py to define properties like trust window, access_level, and location

### Additional Implementation Tips
- **Trust Decay:** Implement time-based trust decay using env.now
- **Device Health Degradation:** Simulate via energy coefficients and buffer overflows in node.py
- **Log-Based Backtracking:** Use logs to detect lateral movement or chain reactions across nodes
- **Adversarial Nodes:** Simulate malicious nodes in ZAM.py test scenarios
- **Test Scenarios:** Configure ZAM.py to test high-load, high-threat, or malicious node scenarios

---

## Code Skeleton: ZTAEngine Class
Below is a Python code skeleton for the ZTAEngine class, implementing all three ZTA pillars and integrating with the simulator’s components.

```python
class ZTAEngine:
    def __init__(self, fog_nodes, tasks, env):
        """Initialize ZTAEngine with nodes, tasks, and environment."""
        self.fog_nodes = fog_nodes
        self.tasks = tasks
        self.env = env
        self.policy_rules = {
            "high_trust": 0.75,
            "medium_trust": 0.5,
            "anomaly_threshold": 0.6,
            "risky_hours": list(range(22, 24)) + list(range(0, 6)),  # 10 PM to 6 AM
            "restricted_zones": ["zone_X"]  # Example restricted locations
        }

    def get_final_trust(self, node):
        """Calculate fused and final trust score for a node."""
        Tperf = node.performance_score  # From node metrics (e.g., CPU, task success)
        Tfb = node.feedback_score      # From peer or external feedback
        Tbeh = node.behavioral_score   # From behavioral patterns
        Tfused = (Tperf + Tfb + Tbeh) / 3
        anomaly_index = self.compute_anomaly_index(node)
        return Tfused / (1 + anomaly_index)

    def compute_anomaly_index(self, node):
        """Compute anomaly index using sliding window (size=5)."""
        node.trust_window.append(self.get_final_trust(node))
        if len(node.trust_window) > 5:
            node.trust_window.pop(0)
        osc = compute_oscillation(node.trust_window)  # Placeholder function
        var = compute_variance(node.trust_window)     # Placeholder function
        cp = detect_change_points(node.trust_window)  # Placeholder function
        return weighted_score(osc, var, cp)           # Placeholder function

    def get_context(self):
        """Gather system context (load, threat, time)."""
        return {
            "load": self.env.load,              # System load from env.py
            "threat_level": self.env.threat_level,  # Threat level from env.py
            "time": self.env.now               # Current time from env.py
        }

    def decide_action(self, node, task):
        """Apply ZTA policy to decide task assignment."""
        Tfinal = self.get_final_trust(node)
        anomaly_index = self.compute_anomaly_index(node)
        context = self.get_context()
        # Pillar 1: Verify Explicitly
        if (anomaly_index > self.policy_rules["anomaly_threshold"] or
            node.health_score < 0.4 or
            node.location in self.policy_rules["restricted_zones"]):
            return "quarantine"
        if (context["time"] in self.policy_rules["risky_hours"] and
            task.criticality == "HIGH"):
            return "assign_test_task"
        # Pillar 2: Least Privilege
        if Tfinal > self.policy_rules["high_trust"]:
            return "assign"
        elif Tfinal > self.policy_rules["medium_trust"]:
            if task.criticality == "LOW":
                return "assign"
            return "monitor"
        else:
            return "quarantine"
        # Pillar 3: Assume Breach
        if node.type == "MaliciousNode":
            return "assign_test_task"
        if node in zone_A and self.detect_trust_drop(node):
            return "quarantine"

    def assign_task(self, node, task):
        """Assign task to node and log decision."""
        node.execute_task(task)
        self.log_decision(node, task, "assigned")

    def assign_test_task(self, node):
        """Assign decoy task to test node behavior."""
        decoy_task = {"id": "decoy", "cpu": 0.1, "criticality": "LOW"}
        node.execute_task(decoy_task)
        self.log_decision(node, decoy_task, "test")

    def detect_trust_drop(self, node):
        """Detect significant trust score drops."""
        if len(node.trust_window) < 2:
            return False
        return node.trust_window[-1] < node.trust_window[-2] * 0.8  # 20% drop

    def log_decision(self, node, task, action):
        """Log decision details for analysis."""
        with open("zta_log.txt", "a") as f:
            f.write(f"Node: {node.id}, Task: {task['id']}, Action: {action}, "
                    f"Tfinal: {self.get_final_trust(node)}, Anomaly: {self.compute_anomaly_index(node)}, "
                    f"Time: {self.env.now}, Load: {self.env.load}\n")
```

**Notes:**
- Helper functions (`compute_oscillation`, `compute_variance`, `detect_change_points`, `weighted_score`) are placeholders to be implemented based on your chosen algorithms.
- The ZTAEngine interacts with fog_nodes (from node.py), tasks (from the dataset), and env (from env.py).
- Each ZTA pillar is addressed in the decision logic.
- Logging outputs detailed records to `zta_log.txt` for analysis.

---

## Final Notes
- This document is a standalone, comprehensive guide for implementing ZTA in your simulator.
- The ZTAEngine code skeleton is flexible and can be extended with specific algorithms for anomaly detection or custom rules.
- Test scenarios in ZAM.py should include edge cases (e.g., high load, malicious nodes, trust drops) to validate ZTA behavior.
- If you need specific implementations for helper functions, additional test scenarios, or further clarification, please specify! 