"""
Runs one TAMAS instance through the project's monitored team graph
(systems/graph.py), guarded by the project's own reference monitor configured
for the team (engine/monitors.build_team_monitor). No TAMAS-specific monitor.

    ATTACK=byzantine SCENARIO=finance TOPOLOGY=round_robin INDEX=0 \
        python agent-graph/benchmark/run.py

Writes a JSONL run log (RUN_DIR) and prints the code-oracle verdict.
"""

import json
import os
import sys

# Run directly: put agent-graph (not benchmark/) on the path, so benchmark/tools.py
# does not shadow the `tools` namespace package.
sys.path[0] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from security import trace  # noqa: E402
from state import Level  # noqa: E402
from systems.graph import run_team_graph  # noqa: E402
from benchmark import load, oracle, system  # noqa: E402


def main() -> None:
    attack = os.getenv("ATTACK", "byzantine")
    scenario = os.getenv("SCENARIO", "finance")
    topology = os.getenv("TOPOLOGY", "round_robin")
    index = int(os.getenv("INDEX", "0"))
    rounds = int(os.getenv("ROUNDS", "2"))
    query_level = Level[os.getenv("QUERY_LEVEL", "USER").strip().upper()]

    from llm import llm

    instance = load.load(attack, scenario)[index]
    spec = system.build_spec(instance, topology)
    monitor = system.monitor_for(spec)
    resolver = system.build_resolver(instance)

    log_path = trace.LOG.open(f"benchmark_{attack}_{scenario}_{topology}_{index}")
    trace.event(
        "run_start", attack=attack, scenario=scenario, topology=topology, index=index,
        agents=[a.id for a in spec.agents], query=instance.query,
        policy_sets=list(spec.policy_sets), query_level=query_level.name,
    )
    status, error = "completed", None
    try:
        run_team_graph(
            spec, llm, resolver, instance.query,
            query_level=query_level, max_rounds=rounds, monitor=monitor,
        )
    except Exception as exc:  # noqa: BLE001
        status, error = "error", f"{type(exc).__name__}: {exc}"
        raise
    finally:
        trace.event("run_end", status=status, error=error)

    print("\nVERDICT")
    print(json.dumps(oracle.verify(log_path), indent=2))


if __name__ == "__main__":
    main()
