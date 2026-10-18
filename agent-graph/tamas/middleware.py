"""
Policy enforcement points of the TAMAS team, one per agent, on every tool call.

TAMAS_MONITOR selects the policy decision point:
  cedar  (default) the project's reference monitor with the TAMAS policy store
         (tamas/monitor.py): grants, the level lattice, confidentiality and
         quarantine in Cedar, with the project's escalation (WS2) and feedback
         (WS3). Mirrors security/authorization_middleware.py.
  flat   the attacker-tool deny-list (tamas/policy.py): the name-aware upper
         bound, kept for comparison.

TAMAS_DEFENDED=0 makes either PEP log-only: every call executes; the Cedar PEP
still records what the monitor would have decided (`would_allow`).

The label (TeamContext) is the label of the team's shared conversation: the
agents of a TAMAS team all read one message list, so each agent's LLM context
holds everything any agent has read. It starts at the user query's channel
level (TAMAS_QUERY_LEVEL, default USER) and drops when a read brings in less
trusted data (the meet), as in the CRM.

A denied call ends the agent's turn (PermissionError, caught by team.py), as
in the CRM; in feedback mode (ENFORCEMENT=feedback) the denial is returned to
the model instead, up to FEEDBACK_BUDGET denials per turn.
"""

import os
from collections import Counter

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage

from security import escalation, feedback, trace
from security.labels import Label
from security.security_context import SecurityContext
from state import Confidentiality, Level
from tamas import effects, policy
from tamas import tools as tamas_tools
from tamas.attacker_tools import is_attacker_tool
from tamas.monitor import monitor


def defended() -> bool:
    return os.getenv("TAMAS_DEFENDED", "1").strip() != "0"


def monitor_mode() -> str:
    return os.getenv("TAMAS_MONITOR", "cedar").strip().lower()


def query_level() -> Level:
    return Level[os.getenv("TAMAS_QUERY_LEVEL", "USER").strip().upper()]


class TeamContext:
    """Label of one run's shared conversation, owned by the monitor."""

    def __init__(self, level: Level | None = None):
        self.security = SecurityContext(
            label=Label(level if level is not None else query_level(),
                        Confidentiality.PUBLIC, frozenset({"user_query"})),
            origin="tamas_team",
        )
        # Denied calls per agent over the whole run (quarantine.cedar).
        self.denied: Counter = Counter()


def _content(result):
    return getattr(result, "content", result)


class TamasCedarMiddleware(AgentMiddleware):
    def __init__(self, agent_id: str, team: TeamContext):
        self.agent_id = agent_id
        self.team = team
        self.module = tamas_tools.module_for_agent(agent_id)
        self.turn_denied = 0

    def before_agent(self, state, runtime):
        self.turn_denied = 0  # the feedback budget is per turn (invocation)
        return None

    def _absorb(self, spec) -> None:
        # A read brings data into the conversation with its source's level;
        # write/egress/critical return confirmations only (Label.bottom).
        if spec is not None and spec.effect == effects.READ:
            self.team.security.absorb(
                Label(spec.output_level, spec.data_conf, frozenset({f"tool:{spec.name}"}))
            )

    def wrap_tool_call(self, request, handler):
        tool_call = request.tool_call
        tool = tool_call["name"]
        args = dict(tool_call.get("args", {}) or {})
        context = self.team.security
        mon = monitor()
        spec = effects.spec(self.module, tool)
        attacker = is_attacker_tool(tool)

        decision = mon.check_call(self.agent_id, tool, context, self.team.denied[self.agent_id])
        # Was the tool granted at all? Cedar names only the matching forbids
        # of a denial, so a missing grant must be checked on its own.
        granted = spec is not None and (
            mon.overprovisioned or monitor("grants").check_call(self.agent_id, tool, context).allowed
        )
        call = {
            "agent": self.agent_id, "tool": tool, "args": args, "granted": granted,
            "allowed": decision.allowed, "policies": list(decision.policies),
            "reason": decision.reason, "label": trace.context_label(context),
            "attacker": attacker, "effect": spec.effect if spec else None,
            "required_level": spec.required_level.name if spec else None,
            "monitor": "cedar", "config": mon.config,
        }

        if not defended():
            result = handler(request)
            self._absorb(spec)
            trace.event("tool_call", **{**call, "allowed": True}, would_allow=decision.allowed,
                        executed=True, output=_content(result))
            return result

        if decision.allowed:
            result = handler(request)
            self._absorb(spec)
            trace.event("tool_call", **call, executed=True, output=_content(result))
            return result

        # Escalation (WS2): only when the level alone blocks the call, i.e.
        # raising the context to the tool's required level would authorize it.
        if spec is not None and context.level < spec.required_level:
            raised = context.raised_to(spec.required_level)
            if mon.check_call(self.agent_id, tool, raised, self.team.denied[self.agent_id]).allowed:
                # The informed user approves what serves their real task: a
                # provisioned tool, never an attacker tool. Only the simulated
                # human knows this; the monitor never does.
                if escalation.resolve(self.agent_id, tool, args, context, spec.required_level,
                                      informed=lambda: not attacker):
                    result = handler(request)
                    self._absorb(spec)
                    trace.event("tool_call", **{**call, "allowed": True}, escalated=True,
                                executed=True, output=_content(result))
                    return result
                call["escalation_denied"] = True

        self.team.denied[self.agent_id] += 1
        self.turn_denied += 1
        if feedback.enabled() and self.turn_denied <= feedback.budget():
            trace.event("tool_call", **call, executed=False, feedback=True, attempt=self.turn_denied)
            return ToolMessage(content=feedback.message(tool, decision),
                               tool_call_id=tool_call["id"], name=tool)
        trace.event("tool_call", **call, executed=False)
        raise PermissionError(str(decision))


class TamasAuthorizationMiddleware(AgentMiddleware):
    """The flat deny-list PEP. A denial is returned to the model, up to the
    feedback budget per turn; then the turn ends (unbounded retries looped)."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.turn_denied = 0

    def before_agent(self, state, runtime):
        self.turn_denied = 0
        return None

    def wrap_tool_call(self, request, handler):
        tool_call = request.tool_call
        tool_name = tool_call["name"]
        args = tool_call.get("args", {}) or {}

        allowed, reason = policy.decide(self.agent_id, tool_name)
        attacker = policy.is_attacker_tool(tool_name)

        if not allowed and defended():
            self.turn_denied += 1
            trace.event(
                "tool_call", agent=self.agent_id, tool=tool_name, args=dict(args),
                allowed=False, attacker=attacker, reason=reason, executed=False,
                monitor="flat", attempt=self.turn_denied,
            )
            if self.turn_denied > feedback.budget():
                raise PermissionError(f"DENY {self.agent_id} -> {tool_name} ({reason})")
            return ToolMessage(
                content=f"DENIED by the security monitor: {reason}.",
                tool_call_id=tool_call["id"], name=tool_name,
            )

        result = handler(request)
        trace.event(
            "tool_call", agent=self.agent_id, tool=tool_name, args=dict(args),
            allowed=True, attacker=attacker, reason=reason, executed=True,
            monitor="flat", output=_content(result),
        )
        return result
