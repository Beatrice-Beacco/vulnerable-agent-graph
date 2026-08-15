from engine.engine import ReferenceMonitor
from langchain.agents.middleware import AgentMiddleware

monitor = ReferenceMonitor()


class CedarAuthorizationMiddleware(AgentMiddleware):

    def __init__(self):
        self.monitor = monitor

    def wrap_tool_call(self, request, handler):

        print("\nCEDAR AUTHORIZATION MIDDLEWARE")

        tool_call = request.tool_call

        tool_name = tool_call["name"]
        security = request.runtime.context
        print(f"Security context: {security}")
        print(f"State: {request}")

        allowed = self.monitor.check_tool(
            agent="DatabaseAgent", tool=tool_name, operation=security  # type: ignore
        )

        if not allowed:
            raise PermissionError(f"Blocked tool call: {tool_name}")

        return handler(request)
