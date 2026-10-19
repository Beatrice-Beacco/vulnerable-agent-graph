"""
Reference monitors per system. The CRM uses the default `ReferenceMonitor()`
(the CRM schema/policies/entities from engine/schema.py). A team system (a
TAMAS instance, or a CRM-style team suite) gets a `ReferenceMonitor` built from
the team schema (generic tool-call model) and the generic/team policy set, with
the system's own agents as entities. Same monitor class, configured by data --
no second monitor.
"""

from dataclasses import replace

from engine.engine import ReferenceMonitor
from engine.schema import POLICY_DIR, build_schema, system_entities
from engine.cedar_util import entity

TEAM_POLICY_DIR = POLICY_DIR / "team"

# Each team policy a monitor may load, as a file. grants + level are the
# generic policies (shared with the CRM); confidentiality + quarantine are the
# team counterparts of the CRM's. A config selects a subset (bench.py).
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


def build_team_monitor(spec, policies=ALL_TEAM_POLICIES) -> ReferenceMonitor:
    """A monitor for a team system: the generic tool-call schema with the
    spec's agents, and the selected generic + team policies."""
    schema = build_schema("team.core.cedarschema", "benchmark", context_type="ToolCallContext")
    entities = [*system_entities(spec), entity("Call", "call")]
    return ReferenceMonitor(schema=schema, policies=team_policies(policies), entities=entities)


def overprovision(spec):
    """A copy of the spec where every agent is granted the tools it was only
    built with (its attacker tools): the over-provisioning ablation, where the
    grant no longer denies attack tools and only the lattice defends."""
    agents = tuple(replace(a, tools=a.built_tools(), ungranted_tools=()) for a in spec.agents)
    return replace(spec, agents=agents)
