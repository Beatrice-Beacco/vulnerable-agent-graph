"""
Experiment driver: runs every (configuration x scenario) cell N times, each
run in its own process (main.py), all logs in one directory. verify.py then
summarizes the directory per scenario and configuration.

    python agent-graph/experiments.py --out runs/exp --runs 10 --configs full,none
    python agent-graph/verify.py runs/exp

A run that ends with an error (e.g. the model server unavailable) is retried;
its log stays in the directory and is reported as invalid.
"""

import argparse
import itertools
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCENARIOS = sorted(p.stem for p in (HERE / "data" / "attacks").glob("*.json"))

DEFENSE_POLICIES = ["binding.cedar", "validation.cedar", "quarantine.cedar", "consensus.cedar"]

# Configuration = policy files left out + analysts per analysis step.
CONFIGS = {
    "full": {"DISABLED_POLICIES": "", "ANALYSTS": "2"},
    "none": {"DISABLED_POLICIES": ",".join(DEFENSE_POLICIES), "ANALYSTS": "1"},
    "no-binding": {"DISABLED_POLICIES": "binding.cedar", "ANALYSTS": "2"},
    "no-validation": {"DISABLED_POLICIES": "validation.cedar", "ANALYSTS": "2"},
    "no-consensus": {"DISABLED_POLICIES": "consensus.cedar", "ANALYSTS": "2"},
    "one-analyst": {"DISABLED_POLICIES": "", "ANALYSTS": "1"},
}


def run_once(out: Path, config: str, scenario: str, index: int, retries: int) -> str:
    env = {
        **os.environ,
        **CONFIGS[config],
        "ATTACK_SCENARIO": scenario,
        "RUN_DIR": str(out),
        "RUN_CONFIG": config,
        "PYTHONIOENCODING": "utf-8",
    }
    stdout_dir = out / "stdout"
    stdout_dir.mkdir(parents=True, exist_ok=True)
    for attempt in range(retries + 1):
        stdout = stdout_dir / f"{config}_{scenario}_{index:02d}_try{attempt}.txt"
        with stdout.open("w", encoding="utf-8") as f:
            try:
                code = subprocess.run(
                    [sys.executable, str(HERE / "main.py")],
                    env=env, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT,
                    timeout=900,
                ).returncode
            except subprocess.TimeoutExpired:
                code = "timeout"
        if code == 0:
            return f"ok      {config:14s} {scenario:28s} #{index}"
    return f"FAILED  {config:14s} {scenario:28s} #{index} ({code})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--configs", default=",".join(CONFIGS))
    parser.add_argument("--scenarios", default=",".join(SCENARIOS))
    parser.add_argument("--parallel", type=int, default=3)
    parser.add_argument("--retries", type=int, default=2)
    args = parser.parse_args()

    configs = args.configs.split(",")
    scenarios = args.scenarios.split(",")
    unknown = (set(configs) - set(CONFIGS)) | (set(scenarios) - set(SCENARIOS))
    if unknown:
        raise SystemExit(f"unknown configs or scenarios: {sorted(unknown)}")

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cells = list(itertools.product(configs, scenarios, range(args.runs)))
    print(f"{len(cells)} runs -> {out}", flush=True)

    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        for line in pool.map(lambda c: run_once(out, *c, args.retries), cells):
            print(line, flush=True)


if __name__ == "__main__":
    main()
