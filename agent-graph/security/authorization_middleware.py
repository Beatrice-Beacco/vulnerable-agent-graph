import os

from engine.tool_contract import output_label, required_level
from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from security import escalation, feedback, trace
from security.security_context import SecurityContext, build_security_context


def _quarantine_hard_only() -> bool:
    """Lever 2 (QUARANTINE_HARD_ONLY=1): a level-only denial -- the call merely
    needed more privilege, and is escalatable -- does not quarantine the agent;
    only a forbidden action (a grant or confidentiality denial) does. Off by
    default, so quarantine counts every denial."""
    return os.getenv("QUARANTINE_HARD_ONLY", "0").strip() == "1"


class CedarAuthorizationMiddleware(AgentMiddleware):
    """
    Policy enforcement point on every tool call of an agent.

    Before the call: the reference monitor authorizes it with the label of the
    agent's LLM context. After the call: the label of the tool output is
    joined into that context, so data read by one call (e.g. a confidential
    record) labels every later call of the same agent (e.g. an egress).
    """

    def __init__(self, agent_id: str, monitor):
        # The system's reference monitor (engine/monitors.build_team_monitor).
        self.monitor = monitor
        self.agent_id = agent_id
        self._turn_denials = 0

    def before_agent(self, state, runtime):
        # The feedback budget is per turn; quarantine (denied_calls) persists.
        self._turn_denials = 0
        return None

    def wrap_tool_call(self, request, handler):
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
            escalatable = context.level < required and self.monitor.check_tool(
                agent=self.agent_id, tool=tool_name, context=raised, args=args
            ).allowed
            if escalatable and escalation.resolve(
                self.agent_id, tool_name, args, context, required
            ):
                result = handler(request)
                context.absorb(output_label(tool_name, args))
                trace.event(
                    "tool_call", **{**call, "allowed": True}, escalated=True,
                    executed=True, output=getattr(result, "content", result),
                )
                return result

            # Quarantine counts this denial unless Lever 2 excuses an
            # escalatable (level-only) one; a forbidden action always counts.
            if not (escalatable and _quarantine_hard_only()):
                context.denied_calls += 1
            self._turn_denials += 1

            # Feedback (WS3): return the denial to the model so it keeps its
            # loop and can try another action, up to a bounded per-turn budget.
            if feedback.enabled() and self._turn_denials <= feedback.budget():
                trace.event(
                    "tool_call", **call, executed=False, escalatable=escalatable,
                    feedback=True, attempt=self._turn_denials,
                )
                return ToolMessage(
                    content=feedback.message(tool_name, decision),
                    tool_call_id=tool_call["id"],
                    name=tool_name,
                )

            trace.event("tool_call", **call, executed=False, escalatable=escalatable)
            raise PermissionError(str(decision))

        result = handler(request)

        context.absorb(output_label(tool_name, args))

        trace.event(
            "tool_call", **call, executed=True, output=getattr(result, "content", result)
        )

        return result
