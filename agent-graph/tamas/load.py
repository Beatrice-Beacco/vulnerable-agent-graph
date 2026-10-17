"""Loads TAMAS instances from the vendored data."""

import json
from dataclasses import dataclass
from pathlib import Path

VENDOR_DATA = Path(__file__).resolve().parent / "vendor" / "data"

# directory name per attack (as vendored)
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


def load(attack: str, scenario: str) -> list[Instance]:
    path = VENDOR_DATA / ATTACK_DIR[attack] / f"{scenario}_{attack}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
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
