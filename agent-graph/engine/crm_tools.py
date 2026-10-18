"""
Declarations of the CRM's tools for the reference monitor (the tool contract,
engine/tool_contract.py). This is everything the monitor used to know about
the CRM tools by name: how a call becomes Cedar requests (one per CRM field
read), the minimum level of each tool (level.cedar), the operation binding and
call targets (binding.cedar, data_subject.cedar), and the label of each tool's
output.
"""

from security.directory import normalize_address, recipient_clearance
from security.labels import Label
from state import Confidentiality, Level, join_confidentiality
from tools.crm import FIELD_CLASSIFICATION, customers, requested_fields

from .schema import entity
from .tool_contract import CedarRequest, ToolDeclaration, register


def _field(name: str) -> str:
    # Resources named by the LLM (fields) must exist: a forbid policy whose
    # condition fails to evaluate (missing attribute) is skipped by Cedar, so
    # an unknown resource could otherwise escape the invariants.
    if name not in FIELD_CLASSIFICATION:
        raise ValueError(f"unknown customer field {name!r}")
    return name


def _crm_context(args: dict, context) -> dict:
    """The operation the executor was asked for (binding.cedar), the targets
    the call itself names, and whether the recipient is the bound customer's
    own registered address (data_subject.cedar)."""
    binding = context.binding
    cedar = {
        "operation": binding.operation,
        "target_customer": binding.customer,
        "requested_fields": sorted(binding.fields),
        "requested_value": binding.value,
        "requested_recipient": binding.recipient,
        "call_customer": str(args.get("customer_id", "")).strip(),
        "call_value": str(args.get("value", "")).strip().lower(),
        "call_recipient": normalize_address(args.get("to", "")),
    }
    registered = normalize_address(customers.get(cedar["target_customer"], {}).get("email", ""))
    cedar["recipient_is_customer_contact"] = bool(registered) and (
        cedar["call_recipient"] == registered
    )
    return cedar


def _read_customer(args: dict) -> list:
    fields = requested_fields(args.get("fields"))
    return [CedarRequest("read_customer", "Field", _field(f)) for f in fields]


def _write_customer(args: dict) -> list:
    field = str(args.get("field", "")).strip().lower()
    return [CedarRequest("write_customer", "Field", _field(field))]


def _delete_customer(args: dict) -> list:
    customer = str(args.get("customer_id", "")).strip()
    return [CedarRequest("delete_customer", "Customer", customer)]


def _send_email(args: dict) -> list:
    recipient = normalize_address(args.get("to", ""))
    if not recipient:
        raise ValueError("send_email without recipient")
    recipient_entity = entity(
        "Recipient", recipient, {"clearance": int(recipient_clearance(recipient))}
    )
    return [CedarRequest("send_email", "Recipient", recipient, (recipient_entity,))]


def _customer_record_label(args: dict) -> Label:
    fields = [f for f in requested_fields(args.get("fields")) if f in FIELD_CLASSIFICATION]
    return Label(
        # Customer records are internal data: a mutation needs at least the
        # INTERNAL level, so their stored content is INTERNAL-trustworthy.
        Level.INTERNAL,
        join_confidentiality(*(FIELD_CLASSIFICATION[f] for f in fields)),
        frozenset(f"crm:{f}" for f in fields),
    )


register(
    # Source tools only bring data into the graph: no policy constrains the
    # call; the output enters the context with its source's label.
    ToolDeclaration(
        "read_email", source=True,
        output_label=lambda args: Label(
            Level.UNTRUSTED_EXTERNAL, Confidentiality.PUBLIC, frozenset({"email"})
        ),
    ),
    ToolDeclaration(
        "read_internal_instruction", source=True,
        output_label=lambda args: Label(
            Level.INTERNAL, Confidentiality.PUBLIC, frozenset({"internal_api"})
        ),
    ),
    # Reads and sends are not level-gated (confidentiality governs them);
    # mutations are: a write needs INTERNAL, a delete the USER level, so even
    # a legitimate internal delete asks the user (WS2).
    ToolDeclaration(
        "read_customer", requests=_read_customer, context=_crm_context,
        output_label=_customer_record_label,
    ),
    ToolDeclaration(
        "write_customer", requests=_write_customer, context=_crm_context,
        required_level=Level.INTERNAL,
    ),
    ToolDeclaration(
        "delete_customer", requests=_delete_customer, context=_crm_context,
        required_level=Level.USER,
    ),
    ToolDeclaration("send_email", requests=_send_email, context=_crm_context),
)
