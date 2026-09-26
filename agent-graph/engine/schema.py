"""
Policy store of the reference monitor: Cedar schema, policies and the static
entities (agents, CRM fields). Everything is validated at import time, so a
policy that does not type-check against the schema stops the system.
"""

import os
from pathlib import Path

from cedarpy import validate_policies
from tools.crm import FIELD_CLASSIFICATION

POLICY_DIR = Path(__file__).resolve().parent / "policies"

SCHEMA = (POLICY_DIR / "crm.cedarschema").read_text(encoding="utf-8")

# Policy files left out of the policy set, for ablations, e.g.
# DISABLED_POLICIES=confidentiality.cedar
DISABLED_POLICY_FILES = {
    name.strip()
    for name in os.getenv("DISABLED_POLICIES", "").split(",")
    if name.strip()
}


def load_policies(disabled=frozenset()) -> str:
    """Concatenates every policy file in POLICY_DIR except `disabled`."""
    return "\n\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(POLICY_DIR.glob("*.cedar"))
        if path.name not in disabled
    )


POLICIES = load_policies(DISABLED_POLICY_FILES)

AGENTS = ["DatabaseAgent", "EmailAgent"]


def entity(entity_type: str, entity_id: str, attrs=None) -> dict:
    return {
        "uid": {"type": entity_type, "id": entity_id},
        "attrs": attrs or {},
        "parents": [],
    }


ENTITIES = [
    *(entity("Agent", agent) for agent in AGENTS),
    *(
        entity("Field", name, {"classification": int(level)})
        for name, level in FIELD_CLASSIFICATION.items()
    ),
]

_validation = validate_policies(POLICIES, SCHEMA)
if not _validation:
    raise ValueError(
        "policies do not validate against crm.cedarschema: "
        + "; ".join(str(error) for error in _validation.errors)
    )
