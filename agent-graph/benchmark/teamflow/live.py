import json
import sys
from pathlib import Path

from benchmark.teamflow import harness
from benchmark.teamflow.adapter import TurnPrompt
from benchmark.teamflow.model import ALLOWLIST, ATTACK, BENIGN, DATAFLOW
from benchmark.teamflow.patterns import PATTERNS
from benchmark.teamflow.suites import BY_ID, CASES, SUITES

RESULTS = Path(__file__).resolve().parents[2] / "runs" / "benchmark" / "teamflow_live_results.jsonl"
PLAN = ((BENIGN, ALLOWLIST), (BENIGN, DATAFLOW), (ATTACK, ALLOWLIST), (ATTACK, DATAFLOW))
UNSCORABLE = ("C03",)


def scorable(case) -> bool:
    return case.pattern not in UNSCORABLE


def sample() -> list:
    suites = list(SUITES)
    return [BY_ID[f"{suites[index % len(suites)]}-{pid}"] for index, pid in enumerate(PATTERNS)]


def selection(arguments: list) -> list:
    if "--all" in arguments:
        return [case for case in CASES if scorable(case)]
    named = [BY_ID[name] for name in arguments if name in BY_ID]
    return named or [case for case in sample() if scorable(case)]


def load() -> list:
    if not RESULTS.exists():
        return []
    return [json.loads(line) for line in RESULTS.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def table(rows: list) -> dict:
    cases = {}
    for row in rows:
        cases.setdefault(row["id"], {"tier": row["tier"], "axis": row["axis"]})[
            f"{row['variant']}/{row['config']}"] = row["reached"]
    return {case_id: runs for case_id, runs in cases.items()
            if all(f"{variant}/{config}" in runs for variant, config in PLAN)}


def report(rows: list) -> None:
    cases = table(rows)
    working = {k: v for k, v in cases.items() if v[f"{BENIGN}/{ALLOWLIST}"]}
    followed = {k: v for k, v in cases.items() if v[f"{ATTACK}/{ALLOWLIST}"]}

    def count(subset: dict, name: str) -> str:
        return f"{sum(1 for runs in subset.values() if runs[name])}/{len(subset)}"

    print(f"\ncases with all four runs: {len(cases)}")
    print(f"benign twin completes, allowlist only: {count(cases, f'{BENIGN}/{ALLOWLIST}')}")
    print(f"benign twin completes, lattice: {count(cases, f'{BENIGN}/{DATAFLOW}')}")
    print(f"  of the twins the team completes undefended: {count(working, f'{BENIGN}/{DATAFLOW}')}")
    print(f"attack succeeds, allowlist only: {count(cases, f'{ATTACK}/{ALLOWLIST}')}")
    print(f"attack succeeds, lattice: {count(cases, f'{ATTACK}/{DATAFLOW}')}")
    print(f"  of the attacks the team follows undefended: {count(followed, f'{ATTACK}/{DATAFLOW}')}")


def main() -> None:
    from llm import llm

    model = TurnPrompt(inner=llm)
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    done = {(row["id"], row["variant"], row["config"]) for row in load()}
    for case in selection(sys.argv[1:]):
        for variant, config in PLAN:
            if (case.id, variant, config) in done:
                continue
            outcome = harness.run(case, variant, config, model=model)
            row = {
                "id": case.id, "suite": case.suite, "pattern": case.pattern, "axis": case.axis,
                "tier": case.tier, "vector": case.vector, "carrier": case.carrier,
                "variant": variant, "config": config,
                "reached": outcome.reached, "denied": list(outcome.denied),
                "decisions": [
                    {"agent": d["agent"], "tool": d["tool"], "args": d["args"],
                     "executed": d["executed"], "policies": list(d["policies"])}
                    for d in outcome.decisions
                ],
                "messages": list(outcome.messages), "error": outcome.error,
            }
            with RESULTS.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row) + "\n")
            print(f"{case.id} {variant}/{config}: reached={outcome.reached} "
                  f"denied={list(outcome.denied)} "
                  f"calls={[d['tool'] for d in outcome.decisions if d['executed']]}", flush=True)
    report(load())


if __name__ == "__main__":
    main()
