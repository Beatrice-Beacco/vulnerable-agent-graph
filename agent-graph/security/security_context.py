from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from security.labels import Label
from state import TaintedValue


@dataclass
class SecurityContext:
    """
    Runtime context of an agent invocation, owned by the reference monitor.

    `label` is the label of everything in the agent's LLM context: the state
    fields the node handed to the agent, joined with the output of every tool
    call it made so far. The LLM is outside the TCB, so anything it produces
    (tool arguments, answer) conservatively carries this label.
    """

    fields: Dict[str, TaintedValue] = field(default_factory=dict)
    label: Label = field(default_factory=Label.top)
    origin: str = "unknown"
    # Calls of this agent the monitor denied so far (quarantine).
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
        """
        Combines the label of new data entering the LLM context (tool output):
        the meet lowers the level if the data is less trusted than the context.
        """
        self.label = self.label.join(label)

    def raised_to(self, level) -> "SecurityContext":
        """
        A copy of this context with the level raised to `level`, for a scoped
        user escalation (WS2). The raise applies only to the authorization it
        is passed to; the context's own label is unchanged.
        """
        from dataclasses import replace

        return SecurityContext(
            fields=self.fields,
            label=replace(self.label, level=max(self.label.level, level)),
            origin=self.origin,
            denied_calls=self.denied_calls,
        )

    def labeled(self, value: Any, source: str) -> TaintedValue:
        """
        Labels a value the agent hands to the shared state. The value was
        produced from the agent's LLM context, so it carries the context label:
        this is how labels propagate from one agent to the next.
        """
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
    """
    Security context of an agent that receives `fields` (labeled values) from
    the shared state. Without labeled fields nothing can be vouched for: the
    context starts at the top of the lattice (untrusted, confidential).
    """
    tainted_fields: Dict[str, TaintedValue] = {
        key: value for key, value in (fields or {}).items() if isinstance(value, TaintedValue)
    }
    if not tainted_fields:
        return SecurityContext(fields={}, label=Label.top(), origin=origin)

    label = Label.bottom()
    for value in tainted_fields.values():
        label = label.join(Label.of(value))
    return SecurityContext(fields=dict(tainted_fields), label=label, origin=origin)
