"""
A system the reference monitor guards, described as data: its agents (each
with a role and the tools it is provisioned), so the monitor's principals,
roles and grants are not a fixed list but come from the spec. A TAMAS instance
is built into one of these (benchmark/system.py).

The agents, roles and provisioned tools build the Cedar Agent entities and the
data-driven grant; the prompt and topology drive the team graph
(systems/graph.py).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentSpec:
    id: str
    # Cedar Role the agent belongs to (grants.cedar), or "" for none.
    role: str = ""
    # Tool names the deployer provisioned for the agent: the grant permits
    # these (grants.cedar -> the Agent entity's `tools`). Source tools may be
    # listed too; they are allowed before the grant check anyway.
    tools: tuple[str, ...] = ()
    # Tools the agent is built with but NOT granted: attacker tools an attack
    # added (T^e), or an over-provisioning ablation. The LLM can call them; the
    # monitor denies them (they are not in the Agent entity's `tools`).
    ungranted_tools: tuple[str, ...] = ()
    # Used by the graph builder (P3), not by the monitor.
    prompt: str = ""

    def built_tools(self) -> tuple[str, ...]:
        """Every tool the agent can attempt: provisioned + ungranted."""
        return (*self.tools, *self.ungranted_tools)


@dataclass(frozen=True)
class SystemSpec:
    name: str
    agents: tuple[AgentSpec, ...]
    # Graph shape (P3): "pipeline" for the CRM, or a team topology.
    topology: str = "pipeline"
    # Policy sets to load for this system (engine/schema.py); "generic" always
    # applies, "crm" adds the CRM-only policies (binding, data_subject, plan
    # checks).
    policy_sets: tuple[str, ...] = ("generic",)

    def roles(self) -> list[str]:
        return sorted({a.role for a in self.agents if a.role})

    def agent(self, agent_id: str) -> AgentSpec:
        for a in self.agents:
            if a.id == agent_id:
                return a
        raise KeyError(agent_id)
