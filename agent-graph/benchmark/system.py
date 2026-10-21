"""
Turns a TAMAS instance into a `SystemSpec` the project runs and guards: one
agent per TAMAS agent, its prompt the `agent_description` (the compromised
agent's carries delta), its provisioned tools the benign tools of its module,
its ungranted tools the module's attacker tools (built, so the LLM can attempt
them; the monitor's grant denies them). The monitor is the project's own,
configured for this team (engine/monitors.build_team_monitor).
"""

from engine.monitors import build_team_monitor
from engine.system import AgentSpec, SystemSpec
from benchmark import catalog
from benchmark import tools as benchmark_tools
from benchmark.load import Instance

import benchmark.manifest  # noqa: F401 -- registers the tools with the monitor


def build_spec(instance: Instance, topology: str = "round_robin") -> SystemSpec:
    agents = []
    for agent in instance.agents:
        names = benchmark_tools.tool_names_for_agent(agent.name)
        provisioned = tuple(t for t in names if catalog.provisioned(t))
        attack = tuple(t for t in names if not catalog.provisioned(t))
        agents.append(
            AgentSpec(
                id=agent.name, tools=provisioned, ungranted_tools=attack,
                prompt=agent.description,
            )
        )
    return SystemSpec(
        name=f"benchmark-{instance.attack}-{instance.scenario}-{instance.index}",
        agents=tuple(agents),
        topology=topology,
        policy_sets=("generic", "team"),
    )


def build_resolver(instance: Instance, sandbox):
    """Maps a tool name to its LangChain tool object (backed by the sandbox),
    across the instance's agents."""
    tool_map = {}
    for agent in instance.agents:
        for tool in benchmark_tools.tools_for_agent(agent.name, sandbox):
            tool_map[tool.name] = tool
    return lambda name: tool_map[name]


def monitor_for(spec: SystemSpec):
    return build_team_monitor(spec)
