from dataclasses import dataclass
from typing import Any, Dict, Optional

from cedarpy import is_authorized
from security.directory import normalize_address, recipient_clearance
from security.security_context import SecurityContext
from tools.crm import FIELD_CLASSIFICATION, requested_fields

from .schema import ENTITIES, POLICIES, SCHEMA, entity


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    agent: str
    tool: str
    reason: str

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"{verdict} {self.agent} -> {self.tool} ({self.reason})"


@dataclass(frozen=True)
class CedarRequest:
    action: str
    resource_type: str
    resource_id: str
    extra_entities: tuple = ()


class ReferenceMonitor:
    policies = POLICIES
    entities = ENTITIES

    def check_tool(
        self,
        agent: str,
        tool: str,
        context: SecurityContext,
        args: Optional[Dict[str, Any]] = None,
    ) -> AuthorizationDecision:
        """
        Authorizes the call `tool(args)` of `agent`, given the label of the
        agent's context. A call can map to several Cedar requests (one per
        CRM field read): all of them must be allowed.
        """
        args = args or {}

        try:
            requests = self._requests(tool, args)
        except ValueError as exc:
            # Unknown tools, fields or arguments are not mediated: fail closed.
            return AuthorizationDecision(False, agent, tool, str(exc))

        cedar_context = context.to_cedar_context()
        print("CEDAR context:", cedar_context)

        permitted = []
        for request in requests:
            allowed, policies, errors = self.authorize(agent, request, cedar_context)
            target = f"{request.action} on {request.resource_type}::{request.resource_id!r}"

            if not allowed:
                if policies:
                    reason = f"{target} forbidden by {', '.join(policies)}"
                else:
                    reason = f"{target} not permitted by any policy"
                if errors:
                    reason += f"; errors: {'; '.join(errors)}"
                return AuthorizationDecision(False, agent, tool, reason)

            permitted.append(f"{target} permitted by {', '.join(policies)}")

        return AuthorizationDecision(True, agent, tool, "; ".join(permitted))

    def authorize(self, agent: str, request: CedarRequest, cedar_context: dict):
        # Structured uids: resource ids come from LLM output and must never be
        # spliced into Cedar syntax.
        cedar_request = {
            "principal": {"type": "Agent", "id": agent},
            "action": {"type": "Action", "id": request.action},
            "resource": {"type": request.resource_type, "id": request.resource_id},
            "context": cedar_context,
        }
        entities = [*self.entities, *request.extra_entities]

        result = is_authorized(cedar_request, self.policies, entities, schema=SCHEMA)

        diagnostics = result.diagnostics
        annotations = getattr(diagnostics, "id_annotations_by_reason", {}) or {}
        policies = [annotations.get(reason, reason) for reason in diagnostics.reasons]
        errors = [str(error) for error in diagnostics.errors]

        return result.allowed, policies, errors

    def _requests(self, tool: str, args: Dict[str, Any]) -> list[CedarRequest]:
        """
        Translates a tool call into Cedar requests. Resources named by the
        LLM (fields) must exist: a forbid policy whose condition fails to
        evaluate (missing attribute) is skipped by Cedar, so an unknown
        resource could otherwise escape the invariants.
        """
        if tool == "read_customer":
            fields = requested_fields(args.get("fields"))
            return [CedarRequest("read_customer", "Field", self._field(f)) for f in fields]

        if tool == "write_customer":
            field = str(args.get("field", "")).strip().lower()
            return [CedarRequest("write_customer", "Field", self._field(field))]

        if tool == "delete_customer":
            customer = str(args.get("customer_id", "")).strip()
            return [CedarRequest("delete_customer", "Customer", customer)]

        if tool == "send_email":
            recipient = normalize_address(args.get("to", ""))
            if not recipient:
                raise ValueError("send_email without recipient")
            recipient_entity = entity(
                "Recipient",
                recipient,
                {"clearance": int(recipient_clearance(recipient))},
            )
            return [
                CedarRequest("send_email", "Recipient", recipient, (recipient_entity,))
            ]

        raise ValueError(f"tool {tool!r} is not mediated by the reference monitor")

    @staticmethod
    def _field(name: str) -> str:
        if name not in FIELD_CLASSIFICATION:
            raise ValueError(f"unknown customer field {name!r}")
        return name
