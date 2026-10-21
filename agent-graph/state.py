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
