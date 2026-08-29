from collections.abc import Mapping

from engine.engine import ReferenceMonitor
from langchain.agents.middleware import AgentMiddleware
from security.security_context import SecurityContext, build_security_context

monitor = ReferenceMonitor()


class CedarAuthorizationMiddleware(AgentMiddleware):

    def __init__(self, agent_id: str):
        self.monitor = monitor
        self.agent_id = agent_id

    def wrap_tool_call(self, request, handler):

        print("\nCEDAR AUTHORIZATION MIDDLEWARE")

        tool_call = request.tool_call

        agent_name = self.agent_id
        tool_name = tool_call["name"]
        args = tool_call.get("args", {}) or {}

        security_context = self._resolve_security_context(
            request, tool_name, agent_name
        )

        allowed = self.monitor.check_tool(
            agent=self.agent_id,
            tool=tool_name,
            context=security_context,
            args=args,
        )

        if not allowed:
            raise PermissionError(f"Blocked tool call: {tool_name}")

        return handler(request)

    def _resolve_security_context(
        self, request, tool_name: str, agent_name: str
    ) -> SecurityContext:
        runtime_context = getattr(request.runtime, "context", None)

        # Unwrap tuple if needed
        if isinstance(runtime_context, tuple) and len(runtime_context) > 0:
            runtime_context = runtime_context[0]

        if isinstance(runtime_context, SecurityContext):
            return runtime_context

        if isinstance(runtime_context, Mapping):
            return build_security_context(
                runtime_context,
                tool_name=tool_name,
                origin=agent_name,
            )

        return build_security_context(
            {},
            origin="missing_context",
        )
