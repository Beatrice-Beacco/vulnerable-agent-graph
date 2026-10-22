"""
A system the reference monitor guards, described as data: its agents (each
with a role and the tools it is built with), so the monitor's principals and
roles are not a fixed list but come from the spec. A benchmark instance is
built into one of these (benchmark/system.py).

The agents and roles build the Cedar Agent entities; the prompt and topology
drive the team graph (systems/graph.py). The grant is not per-agent: a single
global whitelist (grants.cedar, context.whitelisted) authorizes tool calls.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentSpec:
    id: str
    # Cedar Role the agent belongs to, or "" for none.
    role: str = ""
    # Every tool the agent is built with: the LLM may call any of them. The
    # grant does NOT read this list -- authorization is a single global
    # whitelist checked per call (grants.cedar, context.whitelisted) -- so a
    # tool here that is not on the whitelist is offered to the LLM but denied.
    tools: tuple[str, ...] = ()
    # Used by the graph builder (P3), not by the monitor.
    prompt: str = ""


@dataclass(frozen=True)
class SystemSpec:
    name: str
    agents: tuple[AgentSpec, ...]
    # Team topology of the graph (systems/graph.py): round_robin, supervisor
    # or swarm. Which policies guard the system is chosen when its monitor is
    # built (engine/monitors.build_team_monitor), not here.
    topology: str = "round_robin"

    def roles(self) -> list[str]:
        return sorted({a.role for a in self.agents if a.role})

    def agent(self, agent_id: str) -> AgentSpec:
        for a in self.agents:
            if a.id == agent_id:
                return a
        raise KeyError(agent_id)
