from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from security.labels import Label
from state import TaintedValue


@dataclass
class SecurityContext:
    fields: Dict[str, TaintedValue] = field(default_factory=dict)
    label: Label = field(default_factory=Label.top)
    origin: str = "unknown"
    denied_calls: int = 0

    @property
    def level(self):
        return self.label.level

    @property
    def confidentiality(self):
        return self.label.confidentiality

    @property
    def provenance(self):
        return self.label.provenance

    def is_trusted(self) -> bool:
        from state import TRUSTED_THRESHOLD

        return self.label.level >= TRUSTED_THRESHOLD

    def absorb(self, label: Label) -> None:
        self.label = self.label.join(label)

    def raised_to(self, level) -> "SecurityContext":
        from dataclasses import replace

        return SecurityContext(
            fields=self.fields,
            label=replace(self.label, level=max(self.label.level, level)),
            origin=self.origin,
            denied_calls=self.denied_calls,
        )

    def labeled(self, value: Any, source: str) -> TaintedValue:
        return TaintedValue(
            value=value,
            level=self.label.level,
            confidentiality=self.label.confidentiality,
            source=source,
            provenance=sorted(self.label.provenance) + [source],
        )


def build_security_context(
    fields: Optional[Mapping[str, Any]], *, origin: str = "unknown"
) -> SecurityContext:
    tainted_fields: Dict[str, TaintedValue] = {
        key: value for key, value in (fields or {}).items() if isinstance(value, TaintedValue)
    }
    if not tainted_fields:
        return SecurityContext(fields={}, label=Label.top(), origin=origin)

    label = Label.bottom()
    for value in tainted_fields.values():
        label = label.join(Label.of(value))
    return SecurityContext(fields=dict(tainted_fields), label=label, origin=origin)
