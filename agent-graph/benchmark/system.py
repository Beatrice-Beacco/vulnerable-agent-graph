from engine.monitors import build_team_monitor
from engine.system import AgentSpec, SystemSpec
from benchmark import catalog
from benchmark import tools as benchmark_tools
from benchmark.load import Instance

import benchmark.manifest


def build_spec(instance: Instance, topology: str = "round_robin") -> SystemSpec:
    agents = []
    for agent in instance.agents:
        names = benchmark_tools.tool_names_for_agent(agent.name)
        agents.append(
            AgentSpec(id=agent.name, tools=tuple(names), prompt=agent.description)
        )
    return SystemSpec(
        name=f"benchmark-{instance.attack}-{instance.scenario}-{instance.index}",
        agents=tuple(agents),
        topology=topology,
    )


def build_resolver(instance: Instance, sandbox):
    tool_map = {}
    for agent in instance.agents:
        for tool in benchmark_tools.tools_for_agent(agent.name, sandbox):
            tool_map[tool.name] = tool
    return lambda name: tool_map[name]


def monitor_for(spec: SystemSpec):
    return build_team_monitor(spec, whitelist=catalog.WHITELIST)


def informed_user(agent: str, tool: str, args: dict) -> bool:
    return catalog.allowed(tool)
