from security.labels import Label
from state import Confidentiality, Level, join_confidentiality
from tools.crm import FIELD_CLASSIFICATION, requested_fields


def output_label(tool: str, args: dict) -> Label:
    """
    Label of the output of a tool call, combined into the caller's context
    after the call. This is where data enters the graph with its level.
    """
    if tool == "read_customer":
        fields = [f for f in requested_fields(args.get("fields")) if f in FIELD_CLASSIFICATION]
        return Label(
            # Customer records are internal data: a mutation needs at least the
            # INTERNAL level, so their stored content is INTERNAL-trustworthy.
            Level.INTERNAL,
            join_confidentiality(*(FIELD_CLASSIFICATION[f] for f in fields)),
            frozenset(f"crm:{f}" for f in fields),
        )

    if tool == "read_email":
        return Label(
            Level.UNTRUSTED_EXTERNAL, Confidentiality.PUBLIC, frozenset({"email"})
        )

    if tool == "read_internal_instruction":
        return Label(Level.INTERNAL, Confidentiality.PUBLIC, frozenset({"internal_api"}))

    # write_customer, delete_customer, send_email: confirmations only.
    return Label.bottom()
