"""
Multi-agent attacks of TAMAS (arXiv:2511.05269): Byzantine, colluding and
contradicting agents.

An attack compromises agents the way the benchmark does: the system prompt of
a compromised agent becomes p_sys + δ, and the agent may receive attacker
tools T^e on top of its own. The node code (labels, routing) is untouched: it
is part of the TCB, the LLM is not. Every tool call, the attacker's included,
goes through the reference monitor.

The scenario is chosen with ATTACK_SCENARIO=<name> (data/attacks/<name>.json).
Without it no agent is compromised.
"""

from attacks.scenario import (
    ACTIVE,
    AttackScenario,
    attacker_tools,
    load_scenario,
    peer_review,
    system_prompt,
)

__all__ = [
    "ACTIVE",
    "AttackScenario",
    "attacker_tools",
    "load_scenario",
    "peer_review",
    "system_prompt",
]
