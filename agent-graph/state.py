from dataclasses import dataclass
from dataclasses import field

from typing import Annotated
from typing import TypedDict


from enum import IntEnum


class Integrity(IntEnum):
    TRUSTED = 0
    UNTRUSTED = 1


@dataclass
class TaintedValue:
    value: str
    integrity: Integrity
    source: str = "unknown"
    provenance: list[str] = field(default_factory=list)

    def is_trusted(self) -> bool:
        return self.integrity == Integrity.TRUSTED


def taint_policy(integrity_left: Integrity, integrity_right: Integrity) -> Integrity:
    if integrity_left == Integrity.UNTRUSTED or integrity_right == Integrity.UNTRUSTED:
        return Integrity.UNTRUSTED
    return Integrity.TRUSTED


def merge_tainted(left: TaintedValue, right: TaintedValue):
    merged_value = right.value
    if left.value and right.value:
        merged_value = f"{left.value}\n{right.value}"
    elif left.value:
        merged_value = left.value

    merged_source = right.source
    if left.source and right.source:
        merged_source = f"{left.source}\n{right.source}"
    elif left.source:
        merged_source = left.source

    merged_provenance = [*left.provenance, *right.provenance]

    return TaintedValue(
        value=merged_value,
        integrity=taint_policy(left.integrity, right.integrity),
        source=merged_source,
        provenance=merged_provenance,
    )


def join_integrity(*labels: Integrity) -> Integrity:
    """
    Join operator (⊔) of the integrity lattice.

    Trusted ⊔ Trusted = Trusted
    Otherwise = Untrusted
    """

    if all(label == Integrity.TRUSTED for label in labels):
        return Integrity.TRUSTED

    return Integrity.UNTRUSTED


class GraphState(TypedDict):
    email: TaintedValue
    summary: Annotated[TaintedValue, merge_tainted]
    category: Annotated[TaintedValue, merge_tainted]
    customer_request: Annotated[TaintedValue, merge_tainted]
    crm_operation: Annotated[TaintedValue, merge_tainted]
    customer_id: Annotated[TaintedValue, merge_tainted]
