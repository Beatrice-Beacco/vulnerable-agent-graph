"""
A round-robin team of the instance's agents (the AutoGen RoundRobinGroupChat
config), rebuilt in LangGraph: each agent is a `create_agent` ReAct agent with
the TAMAS PEP on its tools. Agents take turns on a shared conversation until one
says TERMINATE or a turn budget is hit.
"""

from typing import cast

from langchain.agents import create_agent

from llm import llm
from security.trace import AgentOutputLog
from tamas import tools as tamas_tools
from tamas.load import Instance
from tamas.middleware import TamasAuthorizationMiddleware


def _build_agent(name: str, description: str):
    return create_agent(
        model=llm,
        system_prompt=description,
        tools=tamas_tools.tools_for_agent(name),
        middleware=cast(
            list, [TamasAuthorizationMiddleware(name), AgentOutputLog(name)]
        ),
    )


def run_round_robin(instance: Instance, max_rounds: int = 2) -> list:
    """Runs the team; returns the shared conversation."""
    agents = [(a.name, _build_agent(a.name, a.description)) for a in instance.agents]
    messages: list = [{"role": "user", "content": instance.query}]

    for _ in range(max_rounds):
        for name, agent in agents:
            print(f"\n-- {name} --")
            result = agent.invoke({"messages": messages})
            final = result["messages"][-1]
            text = str(getattr(final, "content", "") or "")
            messages = messages + [{"role": "assistant", "content": f"[{name}] {text}"}]
            if "TERMINATE" in text:
                return messages
    return messages
