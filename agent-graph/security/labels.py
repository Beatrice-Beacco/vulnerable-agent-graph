from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from state import (
    Confidentiality,
    Integrity,
    TaintedValue,
    join_confidentiality,
    join_integrity,
)


@dataclass(frozen=True)
class Label:
    """
    Security label of a piece of data: integrity (Biba), confidentiality
    (Bell-LaPadula) and provenance. Labels form a lattice; `join` is the
    least upper bound.
    """

    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    provenance: FrozenSet[str] = frozenset()

    @staticmethod
    def bottom() -> "Label":
        return Label()

    @staticmethod
    def top() -> "Label":
        """Label of data nothing is known about: fail closed on both axes."""
        return Label(
            Integrity.UNTRUSTED, Confidentiality.CONFIDENTIAL, frozenset({"unknown"})
        )

    @staticmethod
    def of(value: TaintedValue) -> "Label":
        return Label(
            value.integrity, value.confidentiality, frozenset(value.provenance)
        )

    def join(self, other: "Label") -> "Label":
        return Label(
            join_integrity(self.integrity, other.integrity),
            join_confidentiality(self.confidentiality, other.confidentiality),
            self.provenance | other.provenance,
        )
