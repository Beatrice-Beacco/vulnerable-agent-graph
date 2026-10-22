from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentSpec:
    id: str
    role: str = ""
    tools: tuple[str, ...] = ()
    prompt: str = ""


@dataclass(frozen=True)
class SystemSpec:
    name: str
    agents: tuple[AgentSpec, ...]
    topology: str = "round_robin"

    def roles(self) -> list[str]:
        return sorted({a.role for a in self.agents if a.role})

    def agent(self, agent_id: str) -> AgentSpec:
        for a in self.agents:
            if a.id == agent_id:
                return a
        raise KeyError(agent_id)
