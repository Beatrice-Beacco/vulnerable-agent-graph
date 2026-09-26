from security.labels import Label
from state import Confidentiality, Integrity, join_confidentiality
from tools.crm import FIELD_CLASSIFICATION, requested_fields


def output_label(tool: str, args: dict) -> Label:
    """
    Label of the output of a tool call, joined into the caller's context
    after the call. This is where data enters the graph with its label.
    """
    if tool == "read_customer":
        fields = [f for f in requested_fields(args.get("fields")) if f in FIELD_CLASSIFICATION]
        return Label(
            # Customer records can only be written from trusted contexts
            # (no-untrusted-mutation), so their content is trusted.
            Integrity.TRUSTED,
            join_confidentiality(*(FIELD_CLASSIFICATION[f] for f in fields)),
            frozenset(f"crm:{f}" for f in fields),
        )

    if tool == "read_email":
        return Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC, frozenset({"email"}))

    if tool == "read_internal_instruction":
        return Label(
            Integrity.TRUSTED, Confidentiality.PUBLIC, frozenset({"internal_api"})
        )

    # write_customer, delete_customer, send_email: confirmations only.
    return Label.bottom()
