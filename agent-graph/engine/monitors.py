from engine.engine import ReferenceMonitor
from engine.schema import POLICY_DIR, build_schema, system_entities
from engine.cedar_util import entity

TEAM_POLICY_DIR = POLICY_DIR / "team"

TEAM_POLICY_FILES = {
    "grants": POLICY_DIR / "grants.cedar",
    "level": POLICY_DIR / "level.cedar",
    "confidentiality": TEAM_POLICY_DIR / "confidentiality.cedar",
    "quarantine": TEAM_POLICY_DIR / "quarantine.cedar",
}
ALL_TEAM_POLICIES = ("grants", "level", "confidentiality", "quarantine")


def team_policies(selected=ALL_TEAM_POLICIES) -> str:
    return "\n\n".join(
        TEAM_POLICY_FILES[name].read_text(encoding="utf-8") for name in selected
    )


def build_team_monitor(spec, policies=ALL_TEAM_POLICIES, whitelist=(), whitelist_all=False) -> ReferenceMonitor:
    schema = build_schema("team.core.cedarschema", "benchmark", context_type="ToolCallContext")
    call = entity("Call", "call", {"tools": sorted(whitelist), "all": bool(whitelist_all)})
    entities = [*system_entities(spec), call]
    return ReferenceMonitor(schema=schema, policies=team_policies(policies), entities=entities)
