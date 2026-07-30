from dataclasses import dataclass
from enum import Enum

from typing import Annotated
from typing import TypedDict


class Integrity(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass
class TaintedValue:
    value: str
    integrity: Integrity


def merge_tainted(left: TaintedValue, right: TaintedValue):
    return TaintedValue(
        value=f"{left.value}\n{right.value}",
        integrity=(
            Integrity.UNTRUSTED
            if Integrity.UNTRUSTED in (left.integrity, right.integrity)
            else Integrity.TRUSTED
        ),
    )


class GraphState(TypedDict):
    email: TaintedValue
    summary: Annotated[TaintedValue, merge_tainted]
    category: TaintedValue
    crm_operation: TaintedValue
    customer_id: TaintedValue
