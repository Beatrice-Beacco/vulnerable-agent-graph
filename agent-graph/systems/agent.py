"""
Builds an agent behind the reference monitor: its tool calls pass the PEP
(CedarAuthorizationMiddleware), its context is a SecurityContext, and its
output is logged. Used by the team graph (systems/graph.py) for every system.
"""

from typing import Any, cast

from langchain.agents import create_agent

from security.authorization_middleware import CedarAuthorizationMiddleware
from security.security_context import SecurityContext
from security.trace import AgentOutputLog


def build_monitored_agent(
    llm, agent_id: str, system_prompt: str, tools=(), response_format=None, monitor=None
):
    """`monitor` is the system's reference monitor; its PEP mediates every
    tool call."""
    return create_agent(
        model=llm,
        system_prompt=system_prompt,
        tools=list(tools),
        middleware=cast(
            Any,
            [
                CedarAuthorizationMiddleware(agent_id=agent_id, monitor=monitor),
                AgentOutputLog(agent_id),
            ],
        ),
        context_schema=SecurityContext,
        response_format=response_format,
    )
