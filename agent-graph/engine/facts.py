"""
Policy information point: the attributes the Cedar policies decide on, about
an analysis (a structured CRM operation an analyst derived from a request)
and about the request itself. Nothing here decides: every decision is a
policy in engine/policies/.
"""

import re

from security.directory import normalize_address
from tools.crm import requested_fields

# Placeholders the analysts use for "no value".
EMPTY = {"", "none", "n/a", "null", "-"}

_WORD = re.compile(r"[a-z]+")
_NUMBER = re.compile(r"\d+")
_ADDRESS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _text(value) -> str:
    return str(value if value is not None else "").strip().strip('"').strip("'")


def field_names(value) -> list[str]:
    """Field names as the CRM spells them ("credit limit" -> credit_limit)."""
    if _text(value).lower() in EMPTY:
        return []
    return [name.replace(" ", "_") for name in requested_fields(value)]


def canonical(analysis: dict) -> dict:
    """
    The CRM operation an analysis describes, in canonical form. Triage calls
    the operation "intent", the parser "operation".
    """
    operation = _text(analysis.get("operation", analysis.get("intent"))).lower()
    value = _text(analysis.get("value"))
    recipient = _text(analysis.get("recipient"))
    return {
        "operation": operation,
        "customer_id": _text(analysis.get("customer_id")),
        "fields": field_names(analysis.get("field")),
        "value": "" if value.lower() in EMPTY else value.lower(),
        "recipient": "" if recipient.lower() in EMPTY else normalize_address(recipient),
    }


def request_facts(request: str, value: str) -> dict:
    """What the request contains: words, numbers, addresses, the value."""
    text = request.lower()
    return {
        "request_words": sorted(set(_WORD.findall(text))),
        "request_numbers": sorted(set(_NUMBER.findall(text))),
        "request_addresses": sorted({normalize_address(a) for a in _ADDRESS.findall(text)}),
        "value_in_request": bool(value) and value in text,
    }


def agreement_key(analysis: dict) -> tuple:
    """Two analyses agree when they describe the same CRM operation."""
    op = canonical(analysis)
    return (
        op["operation"],
        op["customer_id"],
        tuple(sorted(op["fields"])),
        op["value"],
        op["recipient"],
    )
