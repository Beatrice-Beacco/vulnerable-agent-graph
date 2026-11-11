from engine.cedar_util import entity
from engine.engine import ReferenceMonitor
from engine.monitors import ALL_TEAM_POLICIES, team_policies
from engine.schema import build_schema, system_entities


def build_agentdojo_monitor(spec, policies=ALL_TEAM_POLICIES, whitelist=(), whitelist_all=False) -> ReferenceMonitor:
    schema = build_schema("team.core.cedarschema", "agentdojo", context_type="ToolCallContext")
    call = entity("Call", "call", {"tools": sorted(whitelist), "all": bool(whitelist_all)})
    entities = [*system_entities(spec), call]
    return ReferenceMonitor(schema=schema, policies=team_policies(policies), entities=entities)
