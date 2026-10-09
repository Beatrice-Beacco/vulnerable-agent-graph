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

# Every agent of the graph is a principal: an attack can hand any of them
# attacker tools, and only grants.cedar decides which tools each may call.
AGENTS = [
    "RouterAgent",
    "EmailReaderAgent",
    "TriageAgent",
    "TriageReviewerAgent",
    "RequestReaderAgent",
    "ParserAgent",
    "ParserReviewerAgent",
    "ArbiterAgent",
    "DatabaseAgent",
    "EmailAgent",
]

# Agents that derive the CRM operation from a request (check/adopt_analysis).
ANALYSTS = [
    "TriageAgent",
    "TriageReviewerAgent",
    "ParserAgent",
    "ParserReviewerAgent",
    "ArbiterAgent",
]

# Words a request must contain for an operation to be derived from it
# (resource.evidence in validation.cedar).
OPERATION_EVIDENCE = {
    "delete_customer": ["delete", "remove", "cancel", "close", "deactivate", "terminate", "erase"],
    "update_customer": ["update", "change", "set", "modify", "correct"],
    "send_customer_data": ["send", "forward", "share", "provide", "tell"],
}


def entity(entity_type: str, entity_id: str, attrs=None, parents=()) -> dict:
    return {
        "uid": {"type": entity_type, "id": entity_id},
        "attrs": attrs or {},
        "parents": [{"type": t, "id": i} for t, i in parents],
    }


ENTITIES = [
    entity("Role", "Analyst"),
    *(
        entity("Agent", agent, parents=[("Role", "Analyst")] if agent in ANALYSTS else [])
        for agent in AGENTS
    ),
    *(
        entity("Operation", name, {"evidence": words})
        for name, words in OPERATION_EVIDENCE.items()
    ),
    *(
        entity("Field", name, {"classification": int(level), "name": name})
        for name, level in FIELD_CLASSIFICATION.items()
    ),
]

_validation = validate_policies(POLICIES, SCHEMA)
if not _validation:
    raise ValueError(
        "policies do not validate against crm.cedarschema: "
        + "; ".join(str(error) for error in _validation.errors)
    )
