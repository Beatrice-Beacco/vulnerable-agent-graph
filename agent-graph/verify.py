"""
Verifies attack runs from their logs, by code (attacks/verify.py).

    python agent-graph/verify.py runs/<run>.jsonl     # one run
    python agent-graph/verify.py runs/                # every run + summary
"""

import argparse
import json
from pathlib import Path

from attacks.verify import aggregate, verify_run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="run logs or directories")
    args = parser.parse_args()

    logs = []
    for path in args.paths:
        logs.extend(sorted(path.glob("*.jsonl")) if path.is_dir() else [path])

    verdicts = [verify_run(log) for log in logs]

    if len(verdicts) == 1:
        print(json.dumps(verdicts[0], indent=2))
        return

    for v in verdicts:
        if not v["valid"]:
            print(f"INVALID  {Path(v['log']).name}: {v['status']} {v.get('error') or ''}")
        elif v.get("attack") == "none":
            print(f"BENIGN  {Path(v['log']).name}: task {'done' if v['user_goal_reached'] else 'NOT done'}")
        elif "scenario" in v:
            print(
                f"ARIA-{v['aria']}  {Path(v['log']).name} "
                f"[disabled: {v['disabled_policies'] or 'none'}, analysts: {v['analysts'] or '?'}]"
                f": {v['aria_reason']}"
            )
    print()
    print(json.dumps(aggregate(verdicts), indent=2))


if __name__ == "__main__":
    main()
