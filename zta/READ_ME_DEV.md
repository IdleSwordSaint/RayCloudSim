# RayCloudSim Developer Guide

RayCloudSim is a Python-based simulator for modeling and analyzing Cloud, Fog, and Edge computing environments. This guide is for developers who want to understand the internals, run experiments, and extend the platform for research (e.g., implementing Zero Trust architectures, new scheduling policies, or custom metrics).

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Main Components](#architecture--main-components)
3. [Directory Structure](#directory-structure)
4. [Simulation Flow: How It Works](#simulation-flow-how-it-works)
5. [Key Classes & Their Roles](#key-classes--their-roles)
6. [Running & Modifying Simulations](#running--modifying-simulations)
7. [How to Extend RayCloudSim](#how-to-extend-raycloudsim)
8. [Practical Tips for Research Extensions](#practical-tips-for-research-extensions)
9. [Where to Find More Information](#where-to-find-more-information)

---

## Project Overview

RayCloudSim simulates distributed computing systems with customizable topologies, nodes, links, and task offloading policies. It is designed for:
- Research on task offloading, resource management, and network behavior
- Experimenting with new architectures (e.g., Zero Trust, federated learning)
- Integrating with ML frameworks for intelligent scheduling

---

## Architecture & Main Components

RayCloudSim is built around a few core abstractions:

- **Env**: The simulation environment. Manages the event loop, task execution, and logging.
- **Scenario**: Defines the network topology (nodes, links) and their properties. Scenarios are typically loaded from JSON config files.
- **Node**: Represents a compute resource (cloud, fog, edge, sensor, etc.). Tracks CPU, buffer, energy, and active tasks.
- **Link**: Represents a network connection between nodes. Tracks bandwidth, latency, and data flows.
- **Task**: Represents a computational job to be offloaded and executed.
- **Policy**: Determines how tasks are scheduled/offloaded (e.g., random, round robin, custom logic).

Supporting modules handle infrastructure management, utilities (e.g., distance calculations), and visualization.

---

## Directory Structure

- **core/**
  - `env.py`: Main simulation environment (class `Env`)
  - `base_scenario.py`: Base class for scenarios (topology, node/link setup)
  - `node.py`: Node model (compute, buffer, energy)
  - `link.py`: Link model (bandwidth, latency)
  - `task.py`: Task/job model
  - `infrastructure.py`: Manages the network graph (nodes/links)
  - `utils.py`: Utilities (locations, data flows, distance, etc.)
  - `configs/`: Example environment config files
- **policies/**: Offloading/scheduling policies (add your own here)
- **eval/**: Datasets, benchmarks, and evaluation scripts
- **examples/**: Example scripts and scenarios
- **docs/**: Additional documentation and images

---

## Simulation Flow: How It Works

1. **Scenario Definition**: A scenario (network topology) is defined via a JSON config and loaded into a `Scenario` class (usually in `examples/scenarios/`).
2. **Environment Setup**: An `Env` object is created with the scenario and environment config.
3. **Task Creation**: Tasks are created and submitted to the environment (can be generated programmatically or from datasets).
4. **Policy Decision**: The offloading/scheduling policy decides where each task should be executed.
5. **Simulation Run**: The environment runs the simulation, processing events (task arrivals, transmissions, executions, completions).
6. **Metrics Collection**: Energy, latency, and other metrics are collected and can be logged or visualized.

---

## Key Classes & Their Roles

### 1. `Env` (core/env.py)
- Manages the simulation event loop (using SimPy)
- Handles task submission, processing, and completion
- Tracks energy consumption, node states, and logs events
- Entry point for running simulations

### 2. `BaseScenario` & Scenario subclasses (core/base_scenario.py, examples/scenarios/)
- Loads network topology from JSON
- Initializes nodes and links
- Can be subclassed for custom scenario logic (e.g., dynamic topologies, special node/link types)

### 3. `Node` (core/node.py)
- Represents a compute node (cloud, fog, edge, etc.)
- Attributes: CPU, buffer, energy coefficients, location, active tasks
- Methods for task execution, energy tracking, buffer management

### 4. `Link` (core/link.py)
- Represents a network link between nodes
- Attributes: bandwidth, latency, distance, data flows
- Methods for bandwidth allocation, latency calculation

### 5. `Task` (core/task.py)
- Represents a computational job
- Attributes: size, cycles per bit, transmission rate, deadline, source/destination
- Tracks transmission, waiting, execution times, and energy

### 6. `Policy` (policies/)
- Determines how tasks are assigned to nodes
- Subclass `BasePolicy` and implement the `act(env, task)` method
- Plug your policy into the simulation loop in your script

---

## Running & Modifying Simulations

1. **Install dependencies**
   ```
   conda create --name raycloudsim python=3.8
   conda activate raycloudsim
   pip install -r requirements.txt
   ```

2. **Run a demo**
   ```
   python examples/demo1.py
   ```
   - Output: Simulation log and energy consumption

3. **Modify a scenario**
   - Edit or create a JSON config in `examples/scenarios/configs/`
   - Create a new scenario class if needed (see `examples/scenarios/scenario_1.py`)

4. **Change the policy**
   - Implement your policy in `policies/`
   - Import and use it in your demo script

5. **Add new metrics or logging**
   - Extend `Env` or `Node` to track new statistics
   - Print or log results as needed

---

## How to Extend RayCloudSim

### 1. Add New Node/Link/Task Attributes
- Edit `core/node.py`, `core/link.py`, or `core/task.py`
- Add new fields (e.g., trust level, security state, custom energy model)
- Update scenario config and initialization logic as needed

### 2. Implement Custom Policies
- Subclass `BasePolicy` in `policies/`
- Implement the `act(env, task)` method (decides where to offload/execute a task)
- Use your policy in your experiment script

### 3. Create New Scenarios
- Copy and adapt an existing scenario class in `examples/scenarios/`
- Define your network in a new JSON config
- Support dynamic or heterogeneous topologies as needed

### 4. Integrate New Formulas or Models
- Add your formulas (e.g., for trust, security, or energy) in the relevant class
- Call your logic during task execution, node state updates, or policy decisions

### 5. Collect and Visualize Custom Metrics
- Extend logging in `Env`, `Node`, or your policy
- Use or adapt visualization scripts in `eval/benchmarks/*/utils/`

---

## Practical Tips for Research Extensions

- **Zero Trust Architecture**: Add trust-related attributes to `Node` and/or `Link`. Implement trust evaluation in your policy or as part of the task execution logic.
- **Security/Privacy Models**: Extend `Task` and `Node` to track security states. Add checks or constraints in your policy.
- **Custom Energy/Latency Models**: Modify the relevant methods in `Node`, `Link`, or `Env`.
- **Batch Experiments**: Write scripts to loop over different configs, policies, or random seeds. Collect results for analysis.
- **Debugging**: Use print/log statements in the event loop. SimPy’s event-based model makes it easy to trace what happens when.

---

## Where to Find More Information

- **Class docstrings**: Each core class is documented with attributes and methods
- **`docs/RayCloudSim.md`**: In-depth modeling and attribute explanations
- **`examples/`**: Progressive scripts from simple to advanced
- **`eval/benchmarks/`**: Realistic datasets and scenarios
- **Original README.md**: High-level overview and quick start
- **SimPy documentation**: For understanding the event-driven simulation engine

---

## FAQ

**Q: Where do I start if I want to add a new security model?**
- Add new attributes to `Node`/`Link`/`Task` as needed
- Update scenario configs to include new parameters
- Implement logic in your policy or in the simulation loop

**Q: How do I run a large batch of experiments?**
- Write a Python script that loops over configs/policies and calls your demo script
- Collect and aggregate results (e.g., to CSV or pandas DataFrame)

**Q: How do I visualize the network or results?**
- Use scripts in `eval/benchmarks/*/utils/vis_topology.py` or adapt for your needs

---

## License

MIT License (see LICENSE file) 