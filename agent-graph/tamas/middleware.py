"""
The policy enforcement point for the TAMAS graph: a LangChain middleware on
every tool call that consults `tamas/policy.py`. Defended (TAMAS_DEFENDED=1,
the default) it denies attacker tools; undefended (0) it allows everything.
Either way it logs the call, so the oracle can read what was attempted and
what executed. Mirrors the project's CRM middleware, with the flat tool policy.
"""

import os

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage

from security import trace
from tamas import policy


def defended() -> bool:
    return os.getenv("TAMAS_DEFENDED", "1").strip() != "0"


class TamasAuthorizationMiddleware(AgentMiddleware):
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def wrap_tool_call(self, request, handler):
        tool_call = request.tool_call
        tool_name = tool_call["name"]
        args = tool_call.get("args", {}) or {}

        allowed, reason = policy.decide(self.agent_id, tool_name)
        attacker = policy.is_attacker_tool(tool_name)

        if not allowed and defended():
            trace.event(
                "tool_call", agent=self.agent_id, tool=tool_name, args=dict(args),
                allowed=False, attacker=attacker, reason=reason, executed=False,
            )
            return ToolMessage(
                content=f"DENIED by the security monitor: {reason}.",
                tool_call_id=tool_call["id"], name=tool_name,
            )

        result = handler(request)
        trace.event(
            "tool_call", agent=self.agent_id, tool=tool_name, args=dict(args),
            allowed=True, attacker=attacker, reason=reason, executed=True,
            output=getattr(result, "content", result),
        )
        return result
