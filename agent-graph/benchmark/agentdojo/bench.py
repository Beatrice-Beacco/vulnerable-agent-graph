import json
import os
from pathlib import Path

from benchmark.agentdojo import manifest
from benchmark.agentdojo.monitor import build_agentdojo_monitor
from engine.monitors import ALL_TEAM_POLICIES
from engine.system import AgentSpec, SystemSpec
from security import dataflow
from security.labels import Label
from security.security_context import SecurityContext
from state import Confidentiality, Level

RESULTS = Path(__file__).resolve().parents[2] / "runs" / "benchmark" / "agentdojo_results.jsonl"
GRANTS = ("grants",)


def _monitor(whitelist, policies):
    spec = SystemSpec(name="agentdojo", agents=(AgentSpec(id=manifest.AGENT, tools=tuple(whitelist)),))
    return build_agentdojo_monitor(spec, policies=policies, whitelist=whitelist)


def _dataflow(whitelist, policies, sink, args, seed, seed_level):
    monitor = _monitor(whitelist, policies)
    os.environ["LEVEL_GATE"] = "dataflow"
    dataflow.reset()
    dataflow.record(seed, Label(seed_level))
    context = SecurityContext(label=Label(Level.USER, Confidentiality.PUBLIC))
    return monitor.check_tool(manifest.AGENT, sink, context, args)


def _coarse(whitelist, policies, sink, args, context_level):
    monitor = _monitor(whitelist, policies)
    os.environ["LEVEL_GATE"] = "coarse"
    context = SecurityContext(label=Label(context_level, Confidentiality.PUBLIC))
    return monitor.check_tool(manifest.AGENT, sink, context, args)


def evaluate(suite: str, case: dict) -> dict:
    whitelist = manifest.SUITES[suite]["whitelist"]
    sink = case["sink_tool"]
    benign = manifest.SUITES[suite]["benign"][sink]

    grants = _dataflow(whitelist, GRANTS, sink, case["args"], case["untrusted"], Level.UNTRUSTED_EXTERNAL)
    full_df = _dataflow(whitelist, ALL_TEAM_POLICIES, sink, case["args"], case["untrusted"], Level.UNTRUSTED_EXTERNAL)
    full_co = _coarse(whitelist, ALL_TEAM_POLICIES, sink, case["args"], Level.UNTRUSTED_EXTERNAL)
    benign_df = _dataflow(whitelist, ALL_TEAM_POLICIES, sink, benign["args"], benign["prompt"], Level.USER)

    if not full_df.allowed:
        actual = "dataflow"
    elif not full_co.allowed:
        actual = "context"
    else:
        actual = "read"

    return {
        "suite": suite,
        "id": case["id"],
        "intent": case["intent"],
        "sink_tool": sink,
        "expected_catch": case.get("catch", "dataflow"),
        "actual_catch": actual,
        "whitelisted_sink": sink in whitelist,
        "attack_grants_allowed": grants.allowed,
        "attack_full_dataflow_allowed": full_df.allowed,
        "attack_full_dataflow_policies": list(full_df.policies),
        "attack_full_coarse_allowed": full_co.allowed,
        "benign_full_allowed": benign_df.allowed,
    }


def run() -> list:
    rows = []
    for suite in manifest.SUITES:
        for case in manifest.SUITES[suite]["injections"]:
            rows.append(evaluate(suite, case))
    return rows


def report(rows: list) -> None:
    suites = list(manifest.SUITES)
    print(f"{'suite':11} {'cases':6} {'wl-slips':9} {'df-catch':9} {'coarse-catch':13} "
          f"{'read-only':10} {'benign-ok':9} {'as-predicted':12}")
    for suite in suites:
        rs = [r for r in rows if r["suite"] == suite]
        n = len(rs)
        slips = sum(1 for r in rs if r["attack_grants_allowed"])
        df = sum(1 for r in rs if not r["attack_full_dataflow_allowed"])
        co = sum(1 for r in rs if not r["attack_full_coarse_allowed"])
        read = sum(1 for r in rs if r["actual_catch"] == "read")
        ben = sum(1 for r in rs if r["benign_full_allowed"])
        pred = sum(1 for r in rs if r["actual_catch"] == r["expected_catch"])
        print(f"{suite:11} {n:<6} {f'{slips}/{n}':9} {f'{df}/{n}':9} {f'{co}/{n}':13} "
              f"{f'{read}/{n}':10} {f'{ben}/{n}':9} {f'{pred}/{n}':12}")
    n = len(rows)
    slips = sum(1 for r in rows if r["attack_grants_allowed"])
    df = sum(1 for r in rows if not r["attack_full_dataflow_allowed"])
    co = sum(1 for r in rows if not r["attack_full_coarse_allowed"])
    read = sum(1 for r in rows if r["actual_catch"] == "read")
    ben = sum(1 for r in rows if r["benign_full_allowed"])
    pred = sum(1 for r in rows if r["actual_catch"] == r["expected_catch"])
    print("-" * 92)
    print(f"{'TOTAL':11} {n:<6} {f'{slips}/{n}':9} {f'{df}/{n}':9} {f'{co}/{n}':13} "
          f"{f'{read}/{n}':10} {f'{ben}/{n}':9} {f'{pred}/{n}':12}")


def main() -> None:
    rows = run()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    report(rows)


if __name__ == "__main__":
    main()
