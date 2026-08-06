from cedarpy import is_authorized
from .schema import POLICIES, ENTITIES
from security.context import SecurityContext
from state import TaintedValue


class ReferenceMonitor:
    policies = POLICIES
    entities = ENTITIES

    def check_flow(self, source_agent, target_agent, state):

        print("\nREFERENCE MONITOR")
        print(f"{source_agent} -> {target_agent}")

        integrity = self.calculate_integrity(state)

        print("Flow integrity:", integrity)

        return True

    def check_tool(self, agent, tool, operation):

        response = self.authorize(agent, operation, operation.integrity)

        print("CEDAR allow:", response)

        return response

    def authorize(self, agent, operation, data):

        request = {
            "principal": f'Agent::"{agent}"',
            "action": f'Action::"{operation.value}"',
            "resource": 'Tool::"CRMDatabase"',
            "context": {"data": {"integrity": data.integrity.value}},
        }

        response = is_authorized(request, POLICIES, ENTITIES)

        return response["decision"] == "allow"

    def calculate_integrity(self, state):

        from state import join_integrity

        labels = []

        for _, value in state.items():

            if hasattr(value, "integrity"):

                labels.append(value.integrity)

        return join_integrity(*labels)
