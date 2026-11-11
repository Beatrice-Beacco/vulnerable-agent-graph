import pytest

pytest.importorskip("cedarpy")

import benchmark.manifest  # noqa: E402,F401
from engine.monitors import build_team_monitor  # noqa: E402
from engine.system import AgentSpec, SystemSpec  # noqa: E402
from engine.tool_contract import required_level  # noqa: E402
from security.labels import Label  # noqa: E402
from security.security_context import SecurityContext  # noqa: E402
from state import Level  # noqa: E402

TOOLS = ("post_on_x", "insert_metadata_and_tags", "summarize_long_content", "execute_limit_order")
SPEC = SystemSpec(name="t", agents=(AgentSpec(id="Poster", tools=TOOLS),))
MON = build_team_monitor(SPEC, whitelist=TOOLS, whitelist_all=True)


@pytest.fixture(autouse=True)
def _coarse(monkeypatch):
    monkeypatch.setenv("LEVEL_GATE", "coarse")


def decide(tool, level):
    return MON.check_tool(agent="Poster", tool=tool,
                          context=SecurityContext(label=Label(level)), args={})


def test_graduated_required_levels():
    assert required_level("summarize_long_content") == Level.UNTRUSTED_EXTERNAL
    assert required_level("post_on_x") == Level.EXTERNAL_KNOWN
    assert required_level("insert_metadata_and_tags") == Level.INTERNAL
    assert required_level("execute_limit_order") == Level.USER


def test_public_egress_clears_at_external_known():
    assert decide("post_on_x", Level.EXTERNAL_KNOWN).allowed
    d = decide("post_on_x", Level.UNTRUSTED_EXTERNAL)
    assert not d.allowed and "insufficient-level" in d.policies


def test_internal_write_still_requires_internal():
    assert decide("insert_metadata_and_tags", Level.INTERNAL).allowed
    assert not decide("insert_metadata_and_tags", Level.EXTERNAL_KNOWN).allowed


def test_critical_still_requires_user():
    assert decide("execute_limit_order", Level.USER).allowed
    assert not decide("execute_limit_order", Level.INTERNAL).allowed
