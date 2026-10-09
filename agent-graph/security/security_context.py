from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from security.directory import normalize_address
from security.labels import Label
from state import TaintedValue


@dataclass(frozen=True)
class OperationBinding:
    """
    The CRM operation an executor agent was asked to execute. The node takes
    it from the graph state, not from the agent's LLM: the monitor allows only
    the calls that execute exactly this operation (binding.cedar), so a
    compromised executor cannot add operations of its own.
    """

    operation: str = ""
    customer: str = ""
    fields: tuple[str, ...] = ()
    value: str = ""
    recipient: str = ""

    @staticmethod
    def of(state) -> "OperationBinding":
        # Imported here: the engine imports this module.
        from engine.facts import EMPTY, field_names

        def get(key: str) -> str:
            value = state.get(key)
            if value is None or value.value is None:
                return ""
            text = str(value.value).strip()
            return "" if text.lower() in EMPTY else text

        return OperationBinding(
            operation=get("operation_type").lower(),
            customer=get("target_customer_id"),
            fields=tuple(field_names(get("update_field"))),
            value=get("update_value").lower(),
            recipient=normalize_address(get("recipient")),
        )


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
    # Set for executor agents only (database, email sender).
    binding: OperationBinding = field(default_factory=OperationBinding)
    # Calls of this invocation the monitor denied (quarantine.cedar).
    denied_calls: int = 0

    @property
    def integrity(self):
        return self.label.integrity

    @property
    def confidentiality(self):
        return self.label.confidentiality

    @property
    def provenance(self):
        return self.label.provenance

    def is_trusted(self) -> bool:
        return self.label.integrity == 0

    def absorb(self, label: Label) -> None:
        """Joins the label of new data entering the LLM context (tool output)."""
        self.label = self.label.join(label)

    def labeled(self, value: Any, source: str) -> TaintedValue:
        """
        Labels a value the agent hands to the graph state. The value was
        produced from the agent's LLM context, so it carries the context label:
        this is how labels propagate from one agent to the next.
        """
        return TaintedValue(
            value=value,
            integrity=self.label.integrity,
            confidentiality=self.label.confidentiality,
            source=source,
            provenance=sorted(self.label.provenance) + [source],
        )

    def to_cedar_context(self) -> Dict[str, Any]:
        return {
            "integrity": int(self.label.integrity),
            "conf": int(self.label.confidentiality),
            "provenance": sorted(self.label.provenance),
            "operation": self.binding.operation,
            "target_customer": self.binding.customer,
            "requested_fields": sorted(self.binding.fields),
            "requested_value": self.binding.value,
            "requested_recipient": self.binding.recipient,
        }


def build_security_context(
    fields: Optional[Mapping[str, Any]],
    *,
    origin: str = "unknown",
    binding: Optional[OperationBinding] = None,
) -> SecurityContext:
    """
    Security context of an agent that receives `fields` from the graph state.
    Without labeled fields nothing can be vouched for: the context starts at
    the top of the lattice (untrusted, confidential).
    """
    fields = fields or {}

    tainted_fields: Dict[str, TaintedValue] = {
        key: value for key, value in fields.items() if isinstance(value, TaintedValue)
    }

    binding = binding or OperationBinding()

    if not tainted_fields:
        return SecurityContext(fields={}, label=Label.top(), origin=origin, binding=binding)

    label = Label.bottom()
    for value in tainted_fields.values():
        label = label.join(Label.of(value))

    return SecurityContext(
        fields=dict(tainted_fields), label=label, origin=origin, binding=binding
    )
