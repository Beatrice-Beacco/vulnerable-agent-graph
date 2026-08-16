from typing import Dict

from cedarpy import is_authorized
from .schema import POLICIES, ENTITIES
from state import TaintedValue, join_integrity


def _normalize_integrity(value):
    if hasattr(value, "name"):
        return value.name.title()
    return str(value)


class ReferenceMonitor:
    policies = POLICIES
    entities = ENTITIES

    def check_flow(self, source_agent, target_agent, state):

        print("\nREFERENCE MONITOR")
        print(f"{source_agent} -> {target_agent}")

        integrity = self.calculate_integrity(state)

        print("Flow integrity:", integrity)

        return True

    def check_tool(self, agent, tool, operation: Dict[str, TaintedValue]):

        integrity = self.calculate_integrity(operation)
        provenance = self.calculate_provenance(operation)
        response = self.authorize(
            agent, tool, {"integrity": integrity, "provenance": provenance}
        )

        print("CEDAR allow:", response)

        return response

    def authorize(self, agent, tool, data):

        integrity = _normalize_integrity(data["integrity"])
        provenance = data["provenance"]

        request = {
            "principal": f'Agent::"{agent}"',
            "action": f'Action::"{tool}"',
            "resource": f'Tool::"{tool}"',
            "context": {
                "data": {
                    "integrity": integrity,
                    "provenance": provenance,
                },
            },
        }

        response = is_authorized(request, POLICIES, ENTITIES)

        return response["decision"] == "allow"

    def calculate_integrity(self, security_context):

        values = [
            value
            for value in security_context.values()
            if isinstance(value, TaintedValue)
        ]

        return join_integrity(*(value.integrity for value in values))

    def calculate_provenance(self, security_context):

        values = [
            value
            for value in security_context.values()
            if isinstance(value, TaintedValue)
        ]

        provenance = []
        for value in values:
            provenance.extend(value.provenance)

        return provenance
