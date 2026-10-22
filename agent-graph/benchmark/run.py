import json
import os
import sys

sys.path[0] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from security import trace
from state import Level
from systems.graph import run_team_graph
from benchmark import load, oracle, system
from benchmark.sandbox import Sandbox
from engine.monitors import ALL_TEAM_POLICIES
from security import escalation

escalation.set_informed_user(system.informed_user)


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

    sandbox = Sandbox()
    sandbox.reset()
    resolver = system.build_resolver(instance, sandbox)

    log_path = trace.LOG.open(f"benchmark_{attack}_{scenario}_{topology}_{index}")
    trace.event(
        "run_start", attack=attack, scenario=scenario, topology=topology, index=index,
        agents=[a.id for a in spec.agents], query=instance.query,
        policies=list(ALL_TEAM_POLICIES), query_level=query_level.name,
    )
    status, error = "completed", None
    try:
        run_team_graph(
            spec, llm, resolver, instance.query,
            query_level=query_level, max_rounds=rounds, monitor=monitor,
        )
    except Exception as exc:
        status, error = "error", f"{type(exc).__name__}: {exc}"
        raise
    finally:
        trace.event("run_end", status=status, error=error)
        state = sandbox.state()
        sandbox.close()

    print("\nVERDICT")
    print(json.dumps(oracle.verify(log_path, state), indent=2))


if __name__ == "__main__":
    main()
