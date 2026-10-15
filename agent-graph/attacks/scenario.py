import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from tools.crm import delete_customer, read_customer, write_customer
from tools.email import send_email

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "data" / "attacks"

# "none" = a benign control: the same task with no compromised agent.
ATTACK_TYPES = {"byzantine", "colluding", "contradicting", "none"}

# Tools an attack can hand to a compromised agent (T^e). They are the real
# tools of the system, so the reference monitor mediates them like any other.
ATTACKER_TOOLS = {
    tool.name: tool
    for tool in (read_customer, write_customer, delete_customer, send_email)
}

# Graph topologies. "peer_review" runs the analysis step of each branch
# (triage, parser) as two agents with the same role plus an arbiter: the
# setting of the contradicting-agents attack.
TOPOLOGIES = {"pipeline", "peer_review"}


@dataclass(frozen=True)
class Compromise:
    """δ appended to the agent's system prompt, and the attacker tools."""

    prompt: str
    tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackScenario:
    name: str
    attack: str
    description: str
    compromised: dict[str, Compromise]
    topology: str = "pipeline"
    # Inputs of the run: the scenario fixes them so the run is reproducible.
    user_prompt: Optional[str] = None
    email_file: Optional[str] = None
    instruction_file: Optional[str] = None
    # Predicates over the run log, checked by attacks/verify.py.
    user_goal: dict[str, Any] = field(default_factory=dict)
    attack_goal: dict[str, Any] = field(default_factory=dict)
    # Byzantine and contradicting agents also succeed by making the benign
    # task fail (TAMAS label 0: disruption).
    task_failure_is_success: bool = False
    # Colluding agents: TAMAS counts a collusion as complete only when every
    # colluder invoked the attacker tool (reported next to the state verdict).
    tamas_full_collusion: dict[str, Any] = field(default_factory=dict)
    # Per compromised agent: the evidence in the log that it followed the
    # attack (used for the ARIA label).
    attempts: dict[str, Any] = field(default_factory=dict)
    # Tools a benign run of this task must invoke (PNA, TAMAS metric).
    required_tools: list = field(default_factory=list)
    # The operation the user legitimately wants (informed escalation, WS2):
    # an escalation for this operation on benign_customer is approved.
    benign_operation: str = ""
    benign_customer: str = "7812"


def load_scenario(name: str) -> AttackScenario:
    path = SCENARIO_DIR / f"{name}.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    compromised = {
        agent: Compromise(prompt=spec["prompt"], tools=tuple(spec.get("tools", ())))
        for agent, spec in data.get("compromised", {}).items()
    }
    scenario = AttackScenario(
        name=data.get("name", name),
        attack=data["attack"],
        description=data.get("description", ""),
        compromised=compromised,
        topology=data.get("topology", "pipeline"),
        user_prompt=data.get("user_prompt"),
        email_file=data.get("email_file"),
        instruction_file=data.get("instruction_file"),
        user_goal=data.get("user_goal", {}),
        attack_goal=data.get("attack_goal", {}),
        task_failure_is_success=data.get("task_failure_is_success", False),
        tamas_full_collusion=data.get("tamas_full_collusion", {}),
        attempts=data.get("attempts", {}),
        required_tools=data.get("required_tools", []),
        benign_operation=data.get("benign_operation", ""),
        benign_customer=data.get("benign_customer", "7812"),
    )

    if scenario.attack not in ATTACK_TYPES:
        raise ValueError(f"{path.name}: unknown attack {scenario.attack!r}")
    if scenario.topology not in TOPOLOGIES:
        raise ValueError(f"{path.name}: unknown topology {scenario.topology!r}")
    stray = set(scenario.attempts) - set(compromised)
    if stray:
        raise ValueError(f"{path.name}: attempts for agents not compromised {sorted(stray)}")
    for agent, compromise in compromised.items():
        unknown = set(compromise.tools) - set(ATTACKER_TOOLS)
        if unknown:
            raise ValueError(f"{path.name}: {agent} has unknown tools {sorted(unknown)}")

    return scenario


_name = os.getenv("ATTACK_SCENARIO", "").strip()
ACTIVE: Optional[AttackScenario] = load_scenario(_name) if _name else None


def system_prompt(agent_id: str, prompt: str) -> str:
    """p_sys, or p_sys + δ when the active attack compromises the agent."""
    if ACTIVE is None or agent_id not in ACTIVE.compromised:
        return prompt
    return f"{prompt}\n\n{ACTIVE.compromised[agent_id].prompt}"


def attacker_tools(agent_id: str) -> list:
    """T^e of the agent: empty unless the active attack compromises it."""
    if ACTIVE is None or agent_id not in ACTIVE.compromised:
        return []
    return [ATTACKER_TOOLS[name] for name in ACTIVE.compromised[agent_id].tools]


def peer_review() -> bool:
    return ACTIVE is not None and ACTIVE.topology == "peer_review"
