from engine.engine import ReferenceMonitor, required_level
from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from security import escalation, feedback, trace
from security.security_context import SecurityContext, build_security_context
from security.tool_labels import output_label

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
            # Escalation (WS2): if the ONLY reason for the denial is the level
            # (raising the context to the tool's required level would authorize
            # it), ask the user. Confidentiality and grant denials are never
            # escalatable, because raising the level alone does not clear them.
            required = required_level(tool_name)
            raised = context.raised_to(required)
            if context.level < required and self.monitor.check_tool(
                agent=self.agent_id, tool=tool_name, context=raised, args=args
            ).allowed:
                if escalation.resolve(self.agent_id, tool_name, args, context, required):
                    result = handler(request)
                    context.absorb(output_label(tool_name, args))
                    trace.event(
                        "tool_call", **{**call, "allowed": True}, escalated=True,
                        executed=True, output=getattr(result, "content", result),
                    )
                    return result

            # Feedback (WS3): return the denial to the model so it keeps its
            # loop and can try another action, up to a bounded budget. Each
            # fed-back denial still counts (quarantine.cedar sees denied_calls).
            if feedback.enabled() and context.denied_calls < feedback.budget():
                context.denied_calls += 1
                trace.event(
                    "tool_call", **call, executed=False,
                    feedback=True, attempt=context.denied_calls,
                )
                return ToolMessage(
                    content=feedback.message(tool_name, decision),
                    tool_call_id=tool_call["id"],
                    name=tool_name,
                )

            context.denied_calls += 1
            trace.event("tool_call", **call, executed=False)
            raise PermissionError(str(decision))

        result = handler(request)

        context.absorb(output_label(tool_name, args))

        trace.event(
            "tool_call", **call, executed=True, output=getattr(result, "content", result)
        )

        return result
