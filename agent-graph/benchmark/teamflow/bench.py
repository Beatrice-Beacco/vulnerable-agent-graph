import json
import time
from pathlib import Path

from benchmark.teamflow import harness
from benchmark.teamflow.model import (
    ATTACK,
    BENIGN,
    BOUNDARY,
    CARRIERS,
    CONFIDENTIALITY,
    CONFIGS,
    CORE,
    DATAFLOW,
    INTEGRITY,
    VARIANTS,
    Case,
)
from benchmark.teamflow.patterns import PATTERNS
from benchmark.teamflow.suites import CASES, SUITES
from engine.monitors import ALL_TEAM_POLICIES
from systems.graph import TEAM_TOPOLOGIES

RUNS = Path(__file__).resolve().parents[2] / "runs" / "benchmark"
RESULTS = RUNS / "teamflow_results.jsonl"
ATTRIBUTION = RUNS / "teamflow_attribution.json"
BASE_TOPOLOGY = "round_robin"


def key(variant: str, config: str) -> str:
    return f"{variant}/{config}"


def evaluate(case: Case, topology: str = BASE_TOPOLOGY) -> dict:
    row = {
        "id": case.id, "suite": case.suite, "pattern": case.pattern, "axis": case.axis,
        "tier": case.tier, "vector": case.vector, "carrier": case.carrier, "topology": topology,
        "runs": {},
    }
    for config in CONFIGS:
        for variant in VARIANTS:
            outcome = harness.run(case, variant, config, topology)
            row["runs"][key(variant, config)] = {
                "reached": outcome.reached,
                "denied": list(outcome.denied),
                "escalations_granted": outcome.escalations_granted,
                "escalations_refused": outcome.escalations_refused,
                "as_predicted": harness.as_predicted(case, variant, config, outcome),
                "error": outcome.error,
            }
    return row


def run(topology: str = BASE_TOPOLOGY, cases=CASES) -> list:
    return [evaluate(case, topology) for case in cases]


def blocked(rows: list, config: str) -> int:
    return sum(1 for row in rows if not row["runs"][key(ATTACK, config)]["reached"])


def completed(rows: list, config: str) -> int:
    return sum(1 for row in rows if row["runs"][key(BENIGN, config)]["reached"])


def escalations(rows: list, config: str, variant: str, field: str) -> int:
    return sum(row["runs"][key(variant, config)][field] for row in rows)


def predicted(rows: list) -> int:
    return sum(1 for row in rows if all(run["as_predicted"] for run in row["runs"].values()))


def mismatches(rows: list) -> list:
    return [(row["id"], name) for row in rows
            for name, run in row["runs"].items() if not run["as_predicted"]]


def invariant(base: list, other: list) -> list:
    reference = {row["id"]: row for row in base}
    differing = []
    for row in other:
        for name, run in row["runs"].items():
            origin = reference[row["id"]]["runs"][name]
            if (run["reached"], run["denied"]) != (origin["reached"], origin["denied"]):
                differing.append((row["id"], name, row["topology"]))
    return differing


def attribution(cases=CASES) -> dict:
    result = {}
    for left_out in ALL_TEAM_POLICIES[1:]:
        kept = tuple(name for name in ALL_TEAM_POLICIES if name != left_out)
        counts = {INTEGRITY: 0, CONFIDENTIALITY: 0}
        for case in cases:
            outcome = harness.run(case, ATTACK, DATAFLOW, policies=kept)
            if not outcome.reached:
                counts[case.axis] += 1
        result[left_out] = counts
    return result


def _table(title: str, groups: list, rows: list) -> None:
    print(f"\n{title}")
    header = f"{'':28} {'n':>4}"
    for config in CONFIGS:
        header += f" {config + ' blk':>16} {config + ' ok':>15}"
    print(header)
    for label, subset in groups:
        line = f"{label:28} {len(subset):>4}"
        for config in CONFIGS:
            line += f" {f'{blocked(subset, config)}/{len(subset)}':>16}"
            line += f" {f'{completed(subset, config)}/{len(subset)}':>15}"
        print(line)


def report(rows: list) -> None:
    n = len(rows)
    print(f"TeamFlow: {n} cases, {len(SUITES)} suites, {len(PATTERNS)} patterns "
          f"(topology {rows[0]['topology']})")
    print("blk = attacks blocked, ok = benign twins completed without intervention")
    _table("By tier", [
        ("all", rows),
        ("core", [r for r in rows if r["tier"] == CORE]),
        ("boundary", [r for r in rows if r["tier"] == BOUNDARY]),
    ], rows)
    _table("By axis", [
        ("integrity", [r for r in rows if r["axis"] == INTEGRITY]),
        ("confidentiality", [r for r in rows if r["axis"] == CONFIDENTIALITY]),
    ], rows)
    _table("By carrier", [
        (carrier, [r for r in rows if r["carrier"] == carrier]) for carrier in CARRIERS
    ], rows)
    _table("By suite", [(name, [r for r in rows if r["suite"] == name]) for name in SUITES], rows)
    _table("By pattern", [
        (f"{pid} {PATTERNS[pid].name}"[:28], [r for r in rows if r["pattern"] == pid])
        for pid in PATTERNS
    ], rows)
    print(f"\nescalations under coarse_user: benign granted "
          f"{escalations(rows, 'coarse_user', BENIGN, 'escalations_granted')}, "
          f"attack refused {escalations(rows, 'coarse_user', ATTACK, 'escalations_refused')}, "
          f"attack granted {escalations(rows, 'coarse_user', ATTACK, 'escalations_granted')}")
    print(f"cases matching every registered prediction: {predicted(rows)}/{n}")
    for case_id, name in mismatches(rows):
        print(f"  MISMATCH {case_id} {name}")


def main() -> None:
    started = time.time()
    results = {topology: run(topology) for topology in TEAM_TOPOLOGIES}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("w", encoding="utf-8") as handle:
        for rows in results.values():
            for row in rows:
                handle.write(json.dumps(row) + "\n")
    report(results[BASE_TOPOLOGY])
    print()
    for topology in TEAM_TOPOLOGIES:
        if topology == BASE_TOPOLOGY:
            continue
        differing = invariant(results[BASE_TOPOLOGY], results[topology])
        print(f"topology {topology}: {len(differing)} runs differ from {BASE_TOPOLOGY}")
        for item in differing:
            print(f"  DIFFERS {item}")
    left_out = attribution()
    ATTRIBUTION.write_text(json.dumps(left_out, indent=2), encoding="utf-8")
    integrity = sum(1 for case in CASES if case.axis == INTEGRITY)
    confidentiality = len(CASES) - integrity
    print("\nleave-one-out under the dataflow gate (attacks blocked; exploratory, not registered)")
    for name, counts in left_out.items():
        print(f"  without {name:16} integrity {counts[INTEGRITY]}/{integrity}  "
              f"confidentiality {counts[CONFIDENTIALITY]}/{confidentiality}")
    runs = sum(len(rows) for rows in results.values()) * len(CONFIGS) * len(VARIANTS)
    runs += len(left_out) * len(CASES)
    print(f"\n{runs} runs in {time.time() - started:.1f}s -> {RESULTS}")


if __name__ == "__main__":
    main()
