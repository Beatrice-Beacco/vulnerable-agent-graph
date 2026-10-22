from dataclasses import dataclass
from dataclasses import field

from typing import Annotated
from typing import TypedDict


from enum import IntEnum


class Level(IntEnum):
    UNTRUSTED_EXTERNAL = 0
    EXTERNAL_KNOWN = 1
    INTERNAL = 2
    USER = 3
    SYSTEM = 4


TRUSTED_THRESHOLD = Level.INTERNAL


class Confidentiality(IntEnum):
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
    return Level(min((int(level) for level in levels), default=int(Level.SYSTEM)))


def join_confidentiality(*labels: Confidentiality) -> Confidentiality:
    return Confidentiality(max((int(label) for label in labels), default=0))
