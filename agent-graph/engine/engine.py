from typing import Any, Dict, Optional

from cedarpy import is_authorized
from .schema import POLICIES, ENTITIES
from security.security_context import SecurityContext


class ReferenceMonitor:
    policies = POLICIES
    entities = ENTITIES

    def check_tool(
        self,
        agent: str,
        tool: str,
        context: SecurityContext,
        args: Optional[Dict[str, Any]] = None,
    ):

        cedar_context = context.to_cedar_context()
        response = self.authorize(agent, tool, cedar_context)

        print("CEDAR allow:", response)

        return response

    def authorize(self, agent, tool, data):

        request = {
            "principal": f'Agent::"{agent}"',
            "action": f'Action::"{tool}"',
            "resource": f'Tool::"{tool}"',
            "context": {
                "data": data,
            },
        }

        response = is_authorized(request, POLICIES, ENTITIES)

        return response.allowed
