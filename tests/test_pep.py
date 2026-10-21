"""Policy enforcement point: escalation, Lever 2, per-turn feedback budget.
Needs langchain; the monitor is a stub, so cedarpy is not needed."""

from types import SimpleNamespace

import pytest

pytest.importorskip("langchain")

from langchain.messages import ToolMessage  # noqa: E402

from security import escalation, trace  # noqa: E402
from security.authorization_middleware import CedarAuthorizationMiddleware  # noqa: E402
from security.labels import Label  # noqa: E402
from security.security_context import SecurityContext  # noqa: E402
from state import Level as L  # noqa: E402

TOOL = "execute_limit_order"  # critical: requires USER

import benchmark.manifest  # noqa: E402,F401  (required levels come from the registry)


class Decision(SimpleNamespace):
    def __str__(self):
        return f"{'ALLOW' if self.allowed else 'DENY'} ({self.reason})"


class LevelOnlyMonitor:
    """Denies below USER with insufficient-level, allows at USER."""

    def check_tool(self, agent, tool, context, args):
        if context.level >= L.USER:
            return Decision(allowed=True, policies=("provisioned-tools",), reason="ok")
        return Decision(allowed=False, policies=("insufficient-level",), reason="level")


class ForbiddenMonitor:
    """Denies at every level (a missing grant)."""

    def check_tool(self, agent, tool, context, args):
        return Decision(allowed=False, policies=(), reason="not permitted")


def request(context, call_id="c1"):
    return SimpleNamespace(
        tool_call={"name": TOOL, "args": {}, "id": call_id},
        runtime=SimpleNamespace(context=context),
    )


def low_context():
    return SecurityContext(label=Label(L.UNTRUSTED_EXTERNAL))


@pytest.fixture(autouse=True)
def env(monkeypatch):
    events = []
    monkeypatch.setattr(trace, "event", lambda kind, **data: events.append((kind, data)))
    monkeypatch.setenv("ENFORCEMENT", "enforce")
    monkeypatch.setenv("USER_POLICY", "always_deny")
    monkeypatch.setenv("QUARANTINE_HARD_ONLY", "0")
    monkeypatch.setattr(escalation, "_informed_user", None)
    return events


def run(pep, context):
    return pep.wrap_tool_call(request(context), lambda req: "done")


def test_level_only_denial_quarantines_by_default():
    ctx = low_context()
    with pytest.raises(PermissionError):
        run(CedarAuthorizationMiddleware("A", LevelOnlyMonitor()), ctx)
    assert ctx.denied_calls == 1


def test_lever2_excuses_a_level_only_denial(monkeypatch):
    monkeypatch.setenv("QUARANTINE_HARD_ONLY", "1")
    ctx = low_context()
    with pytest.raises(PermissionError):
        run(CedarAuthorizationMiddleware("A", LevelOnlyMonitor()), ctx)
    assert ctx.denied_calls == 0


def test_lever2_still_quarantines_a_forbidden_action(monkeypatch):
    monkeypatch.setenv("QUARANTINE_HARD_ONLY", "1")
    ctx = SecurityContext(label=Label(L.SYSTEM))
    with pytest.raises(PermissionError):
        run(CedarAuthorizationMiddleware("A", ForbiddenMonitor()), ctx)
    assert ctx.denied_calls == 1


def test_approved_escalation_runs_once_and_logs_the_recheck(monkeypatch, env):
    monkeypatch.setenv("USER_POLICY", "always_approve")
    ctx = low_context()
    assert run(CedarAuthorizationMiddleware("A", LevelOnlyMonitor()), ctx) == "done"
    assert ctx.level == L.UNTRUSTED_EXTERNAL  # the raise was scoped to the call
    call = next(data for kind, data in env if kind == "tool_call")
    assert call["escalated"] and call["policies"] == ("provisioned-tools",)
    assert call["denied_policies"] == ("insufficient-level",)


def test_feedback_budget_is_per_turn(monkeypatch):
    monkeypatch.setenv("ENFORCEMENT", "feedback")
    monkeypatch.setenv("FEEDBACK_BUDGET", "2")
    pep = CedarAuthorizationMiddleware("A", ForbiddenMonitor())
    ctx = SecurityContext(label=Label(L.SYSTEM))
    assert isinstance(run(pep, ctx), ToolMessage)
    assert isinstance(run(pep, ctx), ToolMessage)
    assert ctx.denied_calls == 0  # fed-back denials do not quarantine
    with pytest.raises(PermissionError):
        run(pep, ctx)
    assert ctx.denied_calls == 1  # the hard deny does
    pep.before_agent(state={}, runtime=None)  # next turn: budget restored
    assert isinstance(run(pep, ctx), ToolMessage)
    assert ctx.denied_calls == 1


def test_informed_user_approves_only_what_the_judge_allows(monkeypatch):
    monkeypatch.setenv("USER_POLICY", "informed")
    escalation.set_informed_user(lambda agent, tool, args: tool == TOOL)
    assert run(CedarAuthorizationMiddleware("A", LevelOnlyMonitor()), low_context()) == "done"
    escalation.set_informed_user(lambda agent, tool, args: False)
    with pytest.raises(PermissionError):
        run(CedarAuthorizationMiddleware("A", LevelOnlyMonitor()), low_context())


def test_informed_policy_without_a_judge_denies(monkeypatch):
    monkeypatch.setenv("USER_POLICY", "informed")
    with pytest.raises(PermissionError):
        run(CedarAuthorizationMiddleware("A", LevelOnlyMonitor()), low_context())
