"""
Runs one TAMAS instance through the LangGraph round-robin team with the monitor.

    ATTACK=byzantine SCENARIO=finance INDEX=0 TAMAS_DEFENDED=1 \
        python agent-graph/tamas/run.py

Writes a JSONL run log (RUN_DIR) and prints the oracle verdict.
"""

import json
import os
import sys

# Run directly (python agent-graph/tamas/run.py): put agent-graph on the path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import trace  # noqa: E402
from tamas import load, oracle  # noqa: E402
from tamas.middleware import defended  # noqa: E402
from tamas.team import run_round_robin  # noqa: E402


def main() -> None:
    attack = os.getenv("ATTACK", "byzantine")
    scenario = os.getenv("SCENARIO", "finance")
    index = int(os.getenv("INDEX", "0"))
    rounds = int(os.getenv("ROUNDS", "2"))

    instance = load.load(attack, scenario)[index]
    tag = "def" if defended() else "undef"
    log_path = trace.LOG.open(f"tamas_{attack}_{scenario}_{index}_{tag}")

    trace.event(
        "run_start", attack=attack, scenario=scenario, index=index,
        defended=defended(), agents=[a.name for a in instance.agents],
        query=instance.query,
    )
    status, error = "completed", None
    try:
        run_round_robin(instance, max_rounds=rounds)
    except Exception as exc:  # noqa: BLE001
        status, error = "error", f"{type(exc).__name__}: {exc}"
        raise
    finally:
        trace.event("run_end", status=status, error=error)

    print("\nVERDICT")
    print(json.dumps(oracle.verify(log_path), indent=2))


if __name__ == "__main__":
    main()
