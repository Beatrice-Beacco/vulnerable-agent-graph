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
    """
    Security label of a piece of data: integrity level (WS1 lattice),
    confidentiality (Bell-LaPadula) and provenance. Combining two labels takes
    the meet of their levels (least trusted) and the join of their
    confidentiality (most secret).
    """

    level: Level = Level.SYSTEM
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    provenance: FrozenSet[str] = frozenset()

    @staticmethod
    def bottom() -> "Label":
        """Identity for combine: most trusted, least secret."""
        return Label(Level.SYSTEM, Confidentiality.PUBLIC)

    @staticmethod
    def top() -> "Label":
        """Label of data nothing is known about: fail closed on both axes."""
        return Label(
            Level.UNTRUSTED_EXTERNAL,
            Confidentiality.CONFIDENTIAL,
            frozenset({"unknown"}),
        )

    @staticmethod
    def of(value: TaintedValue) -> "Label":
        return Label(value.level, value.confidentiality, frozenset(value.provenance))

    def join(self, other: "Label") -> "Label":
        """Combine two labels: meet of levels, join of confidentiality."""
        return Label(
            meet_level(self.level, other.level),
            join_confidentiality(self.confidentiality, other.confidentiality),
            self.provenance | other.provenance,
        )
