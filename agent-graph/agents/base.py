from typing import Any, cast

from langchain.agents import create_agent

import attacks
from security.authorization_middleware import CedarAuthorizationMiddleware
from security.security_context import SecurityContext
from security.trace import AgentOutputLog


def build_agent(llm, agent_id: str, system_prompt: str, tools=(), response_format=None):
    """
    Creates an agent behind the reference monitor. If the active attack
    compromises the agent, δ is appended to its system prompt and it receives
    the attacker tools: their calls go through the same PEP as any other.
    """
    return create_agent(
        model=llm,
        system_prompt=attacks.system_prompt(agent_id, system_prompt),
        tools=[*tools, *attacks.attacker_tools(agent_id)],
        middleware=cast(
            Any,
            [CedarAuthorizationMiddleware(agent_id=agent_id), AgentOutputLog(agent_id)],
        ),
        context_schema=SecurityContext,
        response_format=response_format,
    )
