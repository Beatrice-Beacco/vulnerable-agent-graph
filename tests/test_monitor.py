"""Reference monitor decisions (Equation `allow` in the documentation).
Needs cedarpy."""

import pytest

pytest.importorskip("cedarpy")

import benchmark.manifest  # noqa: E402,F401
from engine.monitors import build_team_monitor  # noqa: E402
from engine.system import AgentSpec, SystemSpec  # noqa: E402
from security.labels import Label  # noqa: E402
from security.security_context import SecurityContext  # noqa: E402
from state import Confidentiality as C  # noqa: E402
from state import Level as L  # noqa: E402

SPEC = SystemSpec(name="t", agents=(
    AgentSpec(id="Trader", tools=("execute_limit_order", "fetch_financial_news",
                                  "execute_irregular_order")),
    AgentSpec(id="Poster", tools=("post_on_x",)),
))
WHITELIST = {"execute_limit_order", "fetch_financial_news", "post_on_x"}
MONITOR = build_team_monitor(SPEC, whitelist=WHITELIST)


def ctx(level=L.USER, conf=C.PUBLIC, denied_tools=()):
    return SecurityContext(label=Label(level, conf), denied_tools=set(denied_tools))


@pytest.fixture(autouse=True)
def _coarse(monkeypatch):
    monkeypatch.setenv("LEVEL_GATE", "coarse")


def decide(agent, tool, context):
    return MONITOR.check_tool(agent=agent, tool=tool, context=context, args={})


def test_provisioned_call_at_sufficient_level_is_allowed():
    d = decide("Trader", "execute_limit_order", ctx(L.USER))
    assert d.allowed and "whitelisted-tool" in d.policies


def test_ungranted_tool_is_denied_by_default():
    d = decide("Trader", "execute_irregular_order", ctx(L.SYSTEM))
    assert not d.allowed and d.policies == ()


def test_low_level_context_is_denied_by_level():
    d = decide("Trader", "execute_limit_order", ctx(L.UNTRUSTED_EXTERNAL))
    assert not d.allowed and "insufficient-level" in d.policies


def test_reads_need_no_level():
    assert decide("Trader", "fetch_financial_news", ctx(L.UNTRUSTED_EXTERNAL)).allowed


def test_egress_of_confidential_context_to_public_sink_is_write_down():
    d = decide("Poster", "post_on_x", ctx(L.USER, C.CONFIDENTIAL))
    assert not d.allowed and "team-no-write-down" in d.policies


def test_quarantined_agent_is_denied():
    d = decide("Trader", "execute_limit_order", ctx(L.USER, denied_tools=("execute_limit_order",)))
    assert not d.allowed and "team-quarantine-denied-agent" in d.policies


def test_quarantine_is_per_tool_not_whole_agent():
    c = ctx(L.USER, denied_tools=("execute_irregular_order",))
    assert decide("Trader", "execute_limit_order", c).allowed


def test_unknown_tool_and_unknown_principal_fail_closed():
    assert not decide("Trader", "not_a_tool", ctx()).allowed
    assert not decide("Nobody", "execute_limit_order", ctx()).allowed


def test_policy_selection_drops_forbids():
    grants_only = build_team_monitor(SPEC, policies=("grants",), whitelist=WHITELIST)
    d = grants_only.check_tool(agent="Trader", tool="execute_limit_order",
                               context=ctx(L.UNTRUSTED_EXTERNAL), args={})
    assert d.allowed
