"""Tool contract, catalog registration and schema generation."""

import json

import pytest

import benchmark.manifest  # noqa: F401 -- registers the catalog
from benchmark.catalog import CATALOG
from engine.schema import build_schema, system_entities
from engine.system import AgentSpec, SystemSpec
from engine.tool_contract import ToolDeclaration, declaration, output_label, register
from security.labels import Label
from security.security_context import SecurityContext
from state import Confidentiality as C
from state import Level as L


def test_every_catalog_tool_is_declared():
    assert len(CATALOG) == 206
    assert all(declaration(name) is not None for name in CATALOG)
    assert declaration("not_a_tool") is None


def test_required_level_is_graduated_per_tool():
    for name, entry in CATALOG.items():
        effect = entry["effect"]
        data_public = entry["data_conf"] == "PUBLIC"
        sink = entry["sink_clearance"]
        sink_public = sink is None or sink == "PUBLIC"
        if effect == "read":
            expected = L.UNTRUSTED_EXTERNAL
        elif effect == "critical":
            expected = L.USER
        elif effect == "write":
            expected = L.EXTERNAL_KNOWN if data_public else L.INTERNAL
        elif effect == "egress":
            expected = L.EXTERNAL_KNOWN if (sink_public and data_public) else L.INTERNAL
        else:
            expected = L.INTERNAL
        assert declaration(name).required_level == expected, name


def test_declarations_do_not_depend_on_origin():
    # The monitor must not know which tools are the attacker's: the Cedar
    # context of a call carries no origin.
    ctx = SecurityContext(label=Label(L.USER))
    for name in CATALOG:
        assert "origin" not in declaration(name).context({}, ctx)


def test_read_output_label_and_confirmation_label():
    read = output_label("fetch_financial_news", {})
    assert read.level == L.UNTRUSTED_EXTERNAL
    assert read.provenance == frozenset({"tool:fetch_financial_news"})
    assert output_label("execute_limit_order", {}) == Label.bottom()


def test_egress_context():
    ctx = SecurityContext(label=Label(L.USER), denied_tools={"alert_caregiver"})
    extra = declaration("alert_caregiver").context({}, ctx)
    assert extra == {"effect": "egress", "data_conf": int(C.CONFIDENTIAL),
                     "sink_clearance": int(C.CONFIDENTIAL), "denied_tools": ["alert_caregiver"]}


def test_register_refuses_a_conflicting_declaration():
    with pytest.raises(ValueError):
        register(ToolDeclaration(name="fetch_financial_news", system="other"))


def test_schema_has_one_action_per_tool_in_the_tool_call_group():
    schema = build_schema("team.core.cedarschema", "benchmark", "ToolCallContext")
    for name in CATALOG:
        assert f'action "{name}" in ["tool_call"] appliesTo' in schema


def test_entities_carry_the_built_tools():
    spec = SystemSpec(name="t", agents=(
        AgentSpec(id="A", role="R", tools=("x", "evil")),))
    entities = system_entities(spec)
    agent = next(e for e in entities if e["uid"]["type"] == "Agent")
    assert agent["attrs"]["tools"] == ["x", "evil"]
    assert agent["parents"] == [{"type": "Role", "id": "R"}]
    json.dumps(entities)  # cedarpy needs plain JSON
