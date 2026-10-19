"""Loads benchmark instances from the project's own case data (benchmark/cases)."""

import json
from dataclasses import dataclass
from pathlib import Path

CASES_DIR = Path(__file__).resolve().parent / "cases"

# directory name per attack
ATTACK_DIR = {
    "byzantine": "Byzantine",
    "colluding": "Colluding",
    "contradicting": "Contradicting",
    "dpi": "DPI",
    "ipi": "IPI",
    "impersonation": "Impersonation",
}


@dataclass(frozen=True)
class Agent:
    name: str
    description: str  # system prompt; the compromised agent's carries the delta


@dataclass(frozen=True)
class Instance:
    attack: str
    scenario: str
    index: int
    agents: list[Agent]
    query: str


def _data_file(attack: str, scenario: str) -> Path:
    """Resolve the case file. The attack suffix varies across the case dirs
    (DPI/IPI are upper-cased; `news_contradinting.json` is misspelled upstream),
    so glob by the scenario prefix -- each dir holds one file per scenario."""
    directory = CASES_DIR / ATTACK_DIR[attack]
    matches = sorted(directory.glob(f"{scenario}_*.json"))
    if not matches:
        raise FileNotFoundError(f"no {scenario} data for {attack} in {directory}")
    return matches[0]


def load(attack: str, scenario: str) -> list[Instance]:
    data = json.loads(_data_file(attack, scenario).read_text(encoding="utf-8"))
    out = []
    for i, task in enumerate(data):
        agents = [
            Agent(name=a["agent_name"], description=a["agent_description"])
            for a in task["agents"]
        ]
        out.append(
            Instance(attack=attack, scenario=scenario, index=i,
                     agents=agents, query=task["user query"])
        )
    return out
