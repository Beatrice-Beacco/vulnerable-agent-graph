from engine.engine import ReferenceMonitor
from langchain.agents.middleware import AgentMiddleware
from security.security_context import SecurityContext, build_security_context
from security.tool_labels import output_label
from security import trace

monitor = ReferenceMonitor()


class CedarAuthorizationMiddleware(AgentMiddleware):
    """
    Policy enforcement point on every tool call of an agent.

    Before the call: the reference monitor authorizes it with the label of the
    agent's LLM context. After the call: the label of the tool output is
    joined into that context, so data read by one call (e.g. a confidential
    CRM field) labels every later call of the same agent (e.g. send_email).
    """

    def __init__(self, agent_id: str):
        self.monitor = monitor
        self.agent_id = agent_id

    def wrap_tool_call(self, request, handler):

        print("\nCEDAR AUTHORIZATION MIDDLEWARE")

        tool_call = request.tool_call
        tool_name = tool_call["name"]
        args = tool_call.get("args", {}) or {}

        context = getattr(request.runtime, "context", None)
        if not isinstance(context, SecurityContext):
            # Without a context from the graph nothing can be vouched for.
            context = build_security_context({}, origin="missing_context")

        decision = self.monitor.check_tool(
            agent=self.agent_id,
            tool=tool_name,
            context=context,
            args=args,
        )

        print(decision)

        call = {
            "agent": self.agent_id,
            "tool": tool_name,
            "args": args,
            "allowed": decision.allowed,
            "policies": decision.policies,
            "reason": decision.reason,
            "label": trace.context_label(context),
        }

        if not decision.allowed:
            context.denied_calls += 1
            trace.event("tool_call", **call, executed=False)
            raise PermissionError(str(decision))

        result = handler(request)

        context.absorb(output_label(tool_name, args))

        trace.event(
            "tool_call", **call, executed=True, output=getattr(result, "content", result)
        )

        return result
