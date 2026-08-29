from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Mapping, Optional
from state import Integrity, TaintedValue, join_integrity
from utils.tool_taints import get_max_taint_for_tool


@dataclass(frozen=True)
class SecurityContext:
    fields: Dict[str, TaintedValue]
    integrity: Integrity
    max_taint: int
    provenance: FrozenSet[str]
    origin: str = "unknown"
    tool_name: Optional[str] = None

    def is_trusted(self) -> bool:
        return self.integrity == Integrity.TRUSTED

    def to_cedar_context(self) -> Dict[str, Any]:
        return {
            "integrity": int(self.integrity.value),
            "maxTaint": int(self.max_taint),
            "provenance": sorted(self.provenance),
            "data": {
                "integrity": int(self.integrity.value),
                "provenance": sorted(self.provenance),
            },
        }


def build_security_context(
    fields: Optional[Mapping[str, Any]],
    tool_name: Optional[str] = None,
    *,
    origin: str = "unknown",
) -> SecurityContext:
    fields = fields or {}

    tainted_fields: Dict[str, TaintedValue] = {
        key: value for key, value in fields.items() if isinstance(value, TaintedValue)
    }

    if not tainted_fields:
        return SecurityContext(
            fields={},
            integrity=Integrity.UNTRUSTED,
            max_taint=Integrity.TRUSTED.value,
            provenance=frozenset({"unknown"}),
            origin=origin,
            tool_name=None,
        )

    integrity = join_integrity(*(value.integrity for value in tainted_fields.values()))

    provenance = frozenset(
        set().union(*[value.provenance for value in tainted_fields.values()])
    )

    max_taint = get_max_taint_for_tool(tool_name if tool_name else "unknown")

    return SecurityContext(
        fields=dict(tainted_fields),
        integrity=integrity,
        max_taint=max_taint,
        provenance=provenance,
        origin=origin,
        tool_name=fields.get("tool_name", None),
    )
