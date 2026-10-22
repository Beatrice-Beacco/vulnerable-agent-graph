from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from state import (
    Confidentiality,
    Level,
    TaintedValue,
    join_confidentiality,
    meet_level,
)


@dataclass(frozen=True)
class Label:
    level: Level = Level.SYSTEM
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    provenance: FrozenSet[str] = frozenset()

    @staticmethod
    def bottom() -> "Label":
        return Label(Level.SYSTEM, Confidentiality.PUBLIC)

    @staticmethod
    def top() -> "Label":
        return Label(
            Level.UNTRUSTED_EXTERNAL,
            Confidentiality.CONFIDENTIAL,
            frozenset({"unknown"}),
        )

    @staticmethod
    def of(value: TaintedValue) -> "Label":
        return Label(value.level, value.confidentiality, frozenset(value.provenance))

    def join(self, other: "Label") -> "Label":
        return Label(
            meet_level(self.level, other.level),
            join_confidentiality(self.confidentiality, other.confidentiality),
            self.provenance | other.provenance,
        )
