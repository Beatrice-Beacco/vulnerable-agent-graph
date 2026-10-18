"""
The project's reference monitor applied to TAMAS: `engine.ReferenceMonitor`
with the TAMAS policy store (tamas/policies). It reuses the monitor's Cedar
evaluation (`_decide`, `authorize`) unchanged; only the schema, the policies
and the entities differ, as the CRM's do from TAMAS's tools.

A call `agent -> tool` is one Cedar request: principal Agent (its module),
resource Tool (labels from tamas/effects.py), context = the label of the
team's shared conversation (level, conf, provenance) + per-agent denials.

Policy configurations (TAMAS_POLICY), for the ablation:
  full     grants (provisioned only) + level + confidentiality + quarantine
  lattice  over-provisioned grants (attacker tools granted) + level +
           confidentiality + quarantine: only the lattice defends
  grants   provisioned grants only: least privilege, no lattice
"""

import os
from functools import lru_cache
from pathlib import Path

from cedarpy import validate_policies

from engine.engine import AuthorizationDecision, CedarRequest, ReferenceMonitor
from engine.schema import entity
from security.security_context import SecurityContext
from tamas import effects, tools as tamas_tools

POLICY_DIR = Path(__file__).resolve().parent / "policies"
SCHEMA = (POLICY_DIR / "tamas.cedarschema").read_text(encoding="utf-8")

# config -> (over-provisioned grants?, policy files left out)
CONFIGS = {
    "full": (False, frozenset()),
    "lattice": (True, frozenset()),
    "grants": (False, frozenset({"level.cedar", "confidentiality.cedar", "quarantine.cedar"})),
}

TOOL_ENTITIES = [
    entity("Tool", s.uid, {
        "module": s.module,
        "name": s.name,
        "effect": s.effect,
        "required_level": int(s.required_level),
        "data_conf": int(s.data_conf),
        "sink_clearance": int(s.sink_clearance),
        "provisioned": s.provisioned,
    })
    for s in effects.SPECS.values()
]


def config_name() -> str:
    name = os.getenv("TAMAS_POLICY", "full").strip().lower()
    if name not in CONFIGS:
        raise ValueError(f"unknown TAMAS_POLICY {name!r}; one of {sorted(CONFIGS)}")
    return name


def _load(disabled: frozenset) -> str:
    extra = {n.strip() for n in os.getenv("TAMAS_DISABLED_POLICIES", "").split(",") if n.strip()}
    return "\n\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted(POLICY_DIR.glob("*.cedar"))
        if p.name not in disabled | extra
    )


class TamasMonitor(ReferenceMonitor):
    schema = SCHEMA
    entities = TOOL_ENTITIES

    def __init__(self, config: str):
        self.config = config
        self.overprovisioned, disabled = CONFIGS[config]
        self.policies = _load(disabled)
        validation = validate_policies(self.policies, SCHEMA)
        if not validation:
            raise ValueError(
                "TAMAS policies do not validate against tamas.cedarschema: "
                + "; ".join(str(e) for e in validation.errors)
            )

    def check_call(
        self, agent: str, tool: str, context: SecurityContext, agent_denied: int = 0
    ) -> AuthorizationDecision:
        module = tamas_tools.module_for_agent(agent)
        spec = effects.spec(module, tool)
        if spec is None:
            # Not a tool of the agent's module: unmediated, fail closed.
            return AuthorizationDecision(False, agent, tool, f"{tool!r} is not a tool of {module}")
        agent_entity = entity("Agent", agent, {"module": module})
        request = CedarRequest("call", "Tool", spec.uid, (agent_entity,))
        cedar_context = {
            "level": int(context.level),
            "conf": int(context.confidentiality),
            "provenance": sorted(context.provenance),
            "overprovisioned": self.overprovisioned,
            "agent_denied": int(agent_denied),
        }
        return self._decide(agent, tool, [request], cedar_context)


@lru_cache(maxsize=None)
def _monitor(config: str) -> TamasMonitor:
    return TamasMonitor(config)


def monitor(config: str | None = None) -> TamasMonitor:
    """The monitor of `config` (default: TAMAS_POLICY), one per config."""
    return _monitor(config or config_name())
