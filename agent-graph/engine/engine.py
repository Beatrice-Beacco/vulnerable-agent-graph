import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cedarpy import is_authorized

from security import dataflow
from security.security_context import SecurityContext

from .tool_contract import CedarRequest, declaration, required_level


def _argument_level() -> bool:
    return os.getenv("ARGUMENT_LEVEL", "0").strip() == "1"


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    agent: str
    tool: str
    reason: str
    policies: tuple[str, ...] = ()

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"{verdict} {self.agent} -> {self.tool} ({self.reason})"


class ReferenceMonitor:
    def __init__(self, schema: str, policies: str, entities: list):
        self.schema = schema
        self.policies = policies
        self.entities = entities

    def check_tool(
        self,
        agent: str,
        tool: str,
        context: SecurityContext,
        args: Optional[Dict[str, Any]] = None,
    ) -> AuthorizationDecision:
        args = args or {}

        tool_declaration = declaration(tool)
        if tool_declaration is None:
            return AuthorizationDecision(
                False, agent, tool, f"tool {tool!r} is not mediated by the reference monitor"
            )
        if tool_declaration.source:
            return AuthorizationDecision(True, agent, tool, "source tool")

        try:
            requests = tool_declaration.requests(args)
        except ValueError as exc:
            return AuthorizationDecision(False, agent, tool, str(exc))

        if dataflow.enabled():
            level = dataflow.level_for(args)
        elif _argument_level():
            level = context.flow_level(args)
        else:
            level = context.label.level
        cedar_context = {
            "tool": tool,
            "level": int(level),
            "conf": int(context.label.confidentiality),
            "provenance": sorted(context.label.provenance),
            **tool_declaration.context(args, context),
            "required_level": int(tool_declaration.required_level),
        }

        return self._decide(agent, tool, requests, cedar_context)

    @property
    def _agent_ids(self) -> frozenset:
        return frozenset(
            e["uid"]["id"] for e in self.entities if e["uid"]["type"] == "Agent"
        )

    def _decide(
        self, agent: str, name: str, requests: list, cedar_context: dict
    ) -> AuthorizationDecision:
        if agent not in self._agent_ids:
            return AuthorizationDecision(False, agent, name, f"unknown principal {agent!r}")
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
