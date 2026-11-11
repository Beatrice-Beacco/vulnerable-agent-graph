import os

from engine.tool_contract import output_label, required_level
from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from security import dataflow, escalation, feedback, trace
from security.security_context import SecurityContext, build_security_context


def _quarantine_hard_only() -> bool:
    return os.getenv("QUARANTINE_HARD_ONLY", "0").strip() == "1"


def _retain_read(context, label, result) -> None:
    if not label.provenance:
        return
    content = getattr(result, "content", result)
    if dataflow.argument_mode():
        context.record_read(content, label)
    if dataflow.enabled():
        dataflow.record(content, label)


class CedarAuthorizationMiddleware(AgentMiddleware):
    def __init__(self, agent_id: str, monitor):
        self.monitor = monitor
        self.agent_id = agent_id
        self._turn_denials = 0

    def before_agent(self, state, runtime):
        self._turn_denials = 0
        return None

    def wrap_tool_call(self, request, handler):
        tool_call = request.tool_call
        tool_name = tool_call["name"]
        args = tool_call.get("args", {}) or {}

        context = getattr(request.runtime, "context", None)
        if not isinstance(context, SecurityContext):
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
            required = required_level(tool_name)
            recheck = None
            if context.level < required:
                recheck = self.monitor.check_tool(
                    agent=self.agent_id, tool=tool_name,
                    context=context.raised_to(required), args=args,
                )
            escalatable = recheck is not None and recheck.allowed
            if escalatable and escalation.resolve(
                self.agent_id, tool_name, args, context, required
            ):
                result = handler(request)
                out = output_label(tool_name, args)
                context.absorb(out)
                _retain_read(context, out, result)
                trace.event(
                    "tool_call",
                    **{**call, "allowed": True, "policies": recheck.policies,
                       "reason": recheck.reason},
                    denied_policies=decision.policies, escalated=True,
                    executed=True, output=getattr(result, "content", result),
                )
                return result

            self._turn_denials += 1

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

            if not (escalatable and _quarantine_hard_only()):
                context.denied_tools.add(tool_name)
            trace.event("tool_call", **call, executed=False, escalatable=escalatable)
            raise PermissionError(str(decision))

        result = handler(request)

        out = output_label(tool_name, args)
        context.absorb(out)
        _retain_read(context, out, result)

        trace.event(
            "tool_call", **call, executed=True, output=getattr(result, "content", result)
        )

        return result
