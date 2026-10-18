from dataclasses import dataclass
from typing import Any, Dict, Optional

from cedarpy import is_authorized
from security.security_context import SecurityContext
from tools.crm import FIELD_CLASSIFICATION

from . import crm_tools  # noqa: F401 -- registers the CRM's tool declarations
from .facts import canonical, request_facts
from .schema import ENTITIES, OPERATION_EVIDENCE, POLICIES, SCHEMA
from .tool_contract import CedarRequest, declaration, required_level  # noqa: F401


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    agent: str
    tool: str
    reason: str
    # Ids of the policies that decided: the forbids of a deny, the permits
    # of an allow.
    policies: tuple[str, ...] = ()

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"{verdict} {self.agent} -> {self.tool} ({self.reason})"


class ReferenceMonitor:
    # Policy store; a subclass may bring its own (tamas/monitor.py does).
    schema = SCHEMA
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
        agent's context. The tool's declaration (engine/tool_contract.py)
        turns the call into Cedar requests -- possibly several, e.g. one per
        CRM field read: all of them must be allowed -- and adds the Cedar
        context the call contributes beyond the caller's label.
        """
        args = args or {}

        tool_declaration = declaration(tool)
        if tool_declaration is None:
            # A tool the monitor knows nothing about is not mediated: fail closed.
            return AuthorizationDecision(
                False, agent, tool, f"tool {tool!r} is not mediated by the reference monitor"
            )
        if tool_declaration.source:
            return AuthorizationDecision(True, agent, tool, "source tool")

        try:
            requests = tool_declaration.requests(args)
        except ValueError as exc:
            # Unknown fields or arguments are not mediated: fail closed.
            return AuthorizationDecision(False, agent, tool, str(exc))

        cedar_context = {
            "level": int(context.label.level),
            "conf": int(context.label.confidentiality),
            "provenance": sorted(context.label.provenance),
            **tool_declaration.context(args, context),
            "required_level": int(tool_declaration.required_level),
        }
        print("CEDAR context:", cedar_context)

        return self._decide(agent, tool, requests, cedar_context)

    def check_analysis(
        self, agent: str, analysis: dict, request: str, context: SecurityContext
    ) -> AuthorizationDecision:
        """
        Authorizes an analysis: the structured CRM operation `agent` derived
        from `request`. validation.cedar and quarantine.cedar decide, from
        facts about the analysis, the request and the analyst.
        """
        op = canonical(analysis)
        try:
            resource = self._operation(op["operation"])
            fields = [self._field(name) for name in op["fields"]]
        except ValueError as exc:
            return AuthorizationDecision(False, agent, "check_analysis", str(exc))

        cedar_context = {
            "level": int(context.label.level),
            "conf": int(context.label.confidentiality),
            "provenance": sorted(context.label.provenance),
            "customer_id": op["customer_id"],
            "fields": fields,
            "field_count": len(fields),
            "value": op["value"],
            "recipient": op["recipient"],
            **request_facts(request, op["value"]),
            "denied_calls": context.denied_calls,
        }
        request_ = CedarRequest("check_analysis", "Operation", resource)
        return self._decide(agent, "check_analysis", [request_], cedar_context)

    def adopt_analysis(
        self, agent: str, analysis: dict, conflicting: int, request: str
    ) -> AuthorizationDecision:
        """
        Authorizes a checked analysis to become the operation the executors
        run, given how many other checked analyses describe another one
        (consensus.cedar) and how many operations the request supports
        (disambiguation.cedar).
        """
        try:
            resource = self._operation(canonical(analysis)["operation"])
        except ValueError as exc:
            return AuthorizationDecision(False, agent, "adopt_analysis", str(exc))
        cedar_request = CedarRequest("adopt_analysis", "Operation", resource)
        return self._decide(
            agent,
            "adopt_analysis",
            [cedar_request],
            {
                "conflicting_analyses": conflicting,
                "operations_in_request": self._operations_in_request(request),
            },
        )

    @staticmethod
    def _operations_in_request(request: str) -> int:
        """How many of the three operations the request supports by its words."""
        words = set(request_facts(request, "")["request_words"])
        return sum(1 for evidence in OPERATION_EVIDENCE.values() if set(evidence) & words)

    def _decide(
        self, agent: str, name: str, requests: list, cedar_context: dict
    ) -> AuthorizationDecision:
        """All the Cedar requests of one decision must be allowed."""
        permitted, permit_ids = [], []
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
                return AuthorizationDecision(False, agent, name, reason, tuple(policies))

            permitted.append(f"{target} permitted by {', '.join(policies)}")
            permit_ids.extend(p for p in policies if p not in permit_ids)

        return AuthorizationDecision(
            True, agent, name, "; ".join(permitted), tuple(permit_ids)
        )

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

        result = is_authorized(cedar_request, self.policies, entities, schema=self.schema)

        diagnostics = result.diagnostics
        annotations = getattr(diagnostics, "id_annotations_by_reason", {}) or {}
        policies = [annotations.get(reason, reason) for reason in diagnostics.reasons]
        errors = [str(error) for error in diagnostics.errors]

        return result.allowed, policies, errors

    @staticmethod
    def _operation(name: str) -> str:
        # Unknown operations fail closed, like unknown fields: a missing
        # entity would make the forbid policies on it skip.
        if name not in OPERATION_EVIDENCE:
            raise ValueError(f"unknown operation {name!r}")
        return name

    @staticmethod
    def _field(name: str) -> str:
        if name not in FIELD_CLASSIFICATION:
            raise ValueError(f"unknown customer field {name!r}")
        return name
