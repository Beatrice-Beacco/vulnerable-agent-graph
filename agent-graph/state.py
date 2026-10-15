from dataclasses import dataclass
from dataclasses import field

from typing import Annotated
from typing import TypedDict


from enum import IntEnum


class Level(IntEnum):
    """
    Integrity lattice of security levels (WS1), higher = more trusted:

        UNTRUSTED_EXTERNAL < EXTERNAL_KNOWN < INTERNAL < USER < SYSTEM

    A data item carries the level of its source. Combining data takes the
    *meet* (the minimum): data derived from an external email and an internal
    record can be trusted only at the external level. So reading tainted
    (low-level) data lowers a context's level. A tool requires a minimum
    level; below it the action is escalated to the user (WS2).

    The 2-point configuration {UNTRUSTED_EXTERNAL, INTERNAL} reproduces the
    old TRUSTED/UNTRUSTED axis: "trusted" is level >= INTERNAL.
    """

    UNTRUSTED_EXTERNAL = 0
    EXTERNAL_KNOWN = 1
    INTERNAL = 2
    USER = 3
    SYSTEM = 4


# "Trusted" in the old 2-point sense: at or above INTERNAL.
TRUSTED_THRESHOLD = Level.INTERNAL


class Confidentiality(IntEnum):
    """
    Confidentiality lattice (Bell-LaPadula levels): PUBLIC < INTERNAL < CONFIDENTIAL.

    The level of a value is the highest level of the data it was derived from.
    A value may only flow to a sink whose clearance is at least its level
    ("no write down", enforced by engine/policies/confidentiality.cedar).
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2


@dataclass
class TaintedValue:
    value: str
    level: Level
    source: str = "unknown"
    provenance: list[str] = field(default_factory=list)
    confidentiality: Confidentiality = Confidentiality.PUBLIC

    def is_trusted(self) -> bool:
        return self.level >= TRUSTED_THRESHOLD


def merge_tainted(left: TaintedValue, right: TaintedValue):
    # If the left side is empty (no prior value), prefer the right value
    # entirely so a trusted producer can overwrite the default untrusted
    # placeholder that the graph initializes.
    left_has_value = bool(left.value)
    right_has_value = bool(right.value)

    if not left_has_value and right_has_value:
        return right

    if left_has_value and not right_has_value:
        return left

    # Both have values: concatenate and take the meet of the levels.
    merged_value = right.value
    if left.value and right.value:
        merged_value = f"{left.value}\n{right.value}"

    merged_source = right.source
    if left.source and right.source:
        merged_source = f"{left.source}\n{right.source}"
    elif left.source:
        merged_source = left.source

    merged_provenance = [*left.provenance, *right.provenance]

    return TaintedValue(
        value=merged_value,
        level=meet_level(left.level, right.level),
        source=merged_source,
        provenance=merged_provenance,
        confidentiality=join_confidentiality(
            left.confidentiality, right.confidentiality
        ),
    )


def meet_level(*levels: Level) -> Level:
    """
    Meet operator (⊓) of the integrity lattice: the least trusted level.
    Combining data of different levels yields data trustworthy only at the
    lowest. The meet of no labels is SYSTEM (top, the identity of meet).
    """

    return Level(min((int(level) for level in levels), default=int(Level.SYSTEM)))


def join_confidentiality(*labels: Confidentiality) -> Confidentiality:
    """
    Join operator (⊔) of the confidentiality lattice: the highest level.
    The join of no labels is PUBLIC (bottom).
    """

    return Confidentiality(max((int(label) for label in labels), default=0))


class GraphState(TypedDict):
    user_prompt: TaintedValue

    # ---- Router ----
    selected_branch: Annotated[TaintedValue, merge_tainted]

    # ---- Branch 1: Customer Support ----
    email: Annotated[TaintedValue, merge_tainted]
    email_summary: Annotated[TaintedValue, merge_tainted]

    # ---- Branch 2: Internal Ops ----
    internal_request: Annotated[TaintedValue, merge_tainted]
    internal_customer_id: Annotated[TaintedValue, merge_tainted]

    # ---- Shared CRM fields ----
    operation_type: Annotated[TaintedValue, merge_tainted]
    target_customer_id: Annotated[TaintedValue, merge_tainted]
    update_field: Annotated[TaintedValue, merge_tainted]
    update_value: Annotated[TaintedValue, merge_tainted]
    # Address the requested customer data is sent to (send_customer_data)
    recipient: Annotated[TaintedValue, merge_tainted]

    # ---- Result of the CRM agent ----
    database_status: str
    # Customer fields read for send_customer_data, handed to the email agent.
    # Labeled with the database agent's context (confidentiality included).
    customer_data: Annotated[TaintedValue, merge_tainted]

    # ---- Result of the email agent ----
    email_status: str

    # ---- Result of the analysis step (triage / parser) ----
    # "rejected" stops the run before any CRM operation (agents/analysis.py).
    analysis_status: str
