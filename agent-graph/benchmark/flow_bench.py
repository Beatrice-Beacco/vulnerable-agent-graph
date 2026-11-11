import json
import os
from pathlib import Path

import benchmark.manifest  # noqa: F401
from benchmark import catalog
from benchmark.flow_cases import CASES, CONFIDENTIALITY, FlowCase
from engine.monitors import ALL_TEAM_POLICIES, build_team_monitor
from engine.tool_contract import declaration
from engine.system import AgentSpec, SystemSpec
from security import dataflow
from security.labels import Label
from security.security_context import SecurityContext
from state import Confidentiality, Level

RESULTS = Path(__file__).resolve().parents[1] / "runs" / "benchmark" / "flow_results.jsonl"

CONFIGS = {
    "grants": ("grants",),
    "full": ALL_TEAM_POLICIES,
}


def _monitor(case: FlowCase, policies):
    spec = SystemSpec(
        name=f"flow-{case.id}",
        agents=(AgentSpec(id=case.agent, tools=case.tools()),),
    )
    return build_team_monitor(spec, policies=policies, whitelist=catalog.WHITELIST)


def _decide(case: FlowCase, variant: str, config: str):
    monitor = _monitor(case, CONFIGS[config])
    read_blocked = None
    if case.axis == CONFIDENTIALITY:
        os.environ["LEVEL_GATE"] = "coarse"
        context = SecurityContext(label=Label(Level.USER, Confidentiality.PUBLIC))
        reads = case.attack_reads if variant == "attack" else case.benign_reads
        for tool in reads:
            decision = monitor.check_tool(case.agent, tool, context, {})
            if not decision.allowed:
                read_blocked = tool
            context.absorb(declaration(tool).output_label({}))
        args = case.attack_args if variant == "attack" else case.benign_args
    else:
        os.environ["LEVEL_GATE"] = "dataflow"
        dataflow.reset()
        if variant == "attack":
            dataflow.record(case.attack_seed, Label(Level.UNTRUSTED_EXTERNAL))
            args = case.attack_args
        else:
            dataflow.record(case.benign_seed, Label(Level.USER))
            args = case.benign_args
        context = SecurityContext(label=Label(Level.USER, Confidentiality.PUBLIC))
    decision = monitor.check_tool(case.agent, case.sink_tool, context, args)
    return decision, read_blocked


def evaluate(case: FlowCase) -> dict:
    row = {
        "id": case.id,
        "scenario": case.scenario,
        "axis": case.axis,
        "sink_tool": case.sink_tool,
        "expected_policy": case.expected_policy,
        "whitelisted_sink": case.sink_tool in catalog.WHITELIST,
    }
    for variant in ("attack", "benign"):
        for config in CONFIGS:
            decision, _ = _decide(case, variant, config)
            row[f"{variant}_{config}_allowed"] = decision.allowed
            row[f"{variant}_{config}_policies"] = list(decision.policies)
    return row


def run() -> list:
    return [evaluate(case) for case in CASES]


def _verdict(row: dict) -> str:
    attack_slips = row["attack_grants_allowed"]
    attack_caught = (not row["attack_full_allowed"]) and (
        row["expected_policy"] in row["attack_full_policies"]
    )
    benign_kept = row["benign_full_allowed"]
    return "PASS" if (attack_slips and attack_caught and benign_kept) else "FAIL"


def report(rows: list) -> None:
    print(f"{'case':26} {'axis':15} {'sink':26} {'wl?':4} "
          f"{'atk/grants':11} {'atk/full':22} {'ben/full':9} {'verdict':7}")
    for row in rows:
        atk_full = "DENY " + ",".join(row["attack_full_policies"]) if not row["attack_full_allowed"] else "ALLOW"
        print(f"{row['id']:26} {row['axis']:15} {row['sink_tool']:26} "
              f"{('yes' if row['whitelisted_sink'] else 'no'):4} "
              f"{('ALLOW' if row['attack_grants_allowed'] else 'DENY'):11} "
              f"{atk_full:22} "
              f"{('ALLOW' if row['benign_full_allowed'] else 'DENY'):9} "
              f"{_verdict(row):7}")
    passed = sum(1 for r in rows if _verdict(r) == "PASS")
    conf = [r for r in rows if r["axis"] == CONFIDENTIALITY]
    print()
    print(f"cases: {len(rows)}  passed: {passed}  "
          f"confidentiality: {len(conf)}  integrity: {len(rows) - len(conf)}")
    print("whitelist-only (grants) attack success: "
          f"{sum(1 for r in rows if r['attack_grants_allowed'])}/{len(rows)}")
    print("whitelist+lattice (full) attack success: "
          f"{sum(1 for r in rows if r['attack_full_allowed'])}/{len(rows)}")
    print("full over-blocks benign: "
          f"{sum(1 for r in rows if not r['benign_full_allowed'])}/{len(rows)}")


def main() -> None:
    rows = run()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    report(rows)


if __name__ == "__main__":
    main()
