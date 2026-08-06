from cedar.engine import ReferenceMonitor
from langchain.agents.middleware import AgentMiddleware

monitor = ReferenceMonitor()


class CedarAuthorizationMiddleware(AgentMiddleware):

    def __init__(self):
        self.monitor = monitor

    def wrap_tool_call(self, request, handler):

        print("\nCEDAR AUTHORIZATION MIDDLEWARE")
        print(f"Request: {request}")
        print(f"Tool: {request.tool_call}")
        print(f"Args: {request.tool_call['args']}")

        tool_call = request.tool_call

        tool_name = tool_call["name"]

        allowed = self.monitor.check_tool(
            agent="DatabaseAgent", tool=tool_name, operation=tool_name  # operation,
        )

        if not allowed:
            raise PermissionError(f"Blocked tool call: {tool_name}")

        return handler(request)
