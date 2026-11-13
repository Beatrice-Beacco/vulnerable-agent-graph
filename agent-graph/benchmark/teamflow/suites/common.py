from typing import Dict, Tuple

from benchmark.teamflow.model import ROLES, AgentDef, Suite, ToolDef


def make_suite(name: str, domain: str, agents: Dict[str, Tuple[str, str]],
               tools: Dict[str, Tuple[str, Tuple[str, ...], str]]) -> Suite:
    return Suite(
        name=name,
        domain=domain,
        agents=tuple(AgentDef(role, *agents[role]) for role in ROLES),
        tools=tuple(ToolDef(slot, *spec) for slot, spec in tools.items()),
    )
