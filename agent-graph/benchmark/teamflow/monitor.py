from engine.cedar_util import entity
from engine.engine import ReferenceMonitor
from engine.monitors import ALL_TEAM_POLICIES, team_policies
from engine.schema import build_schema, system_entities

from benchmark.teamflow.manifest import SYSTEM


def build_teamflow_monitor(spec, policies=ALL_TEAM_POLICIES, whitelist=()) -> ReferenceMonitor:
    schema = build_schema("team.core.cedarschema", SYSTEM, context_type="ToolCallContext")
    call = entity("Call", "call", {"tools": sorted(whitelist), "all": False})
    entities = [*system_entities(spec), call]
    return ReferenceMonitor(schema=schema, policies=team_policies(policies), entities=entities)
