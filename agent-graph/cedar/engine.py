from cedarpy import is_authorized
from .schema import POLICIES, ENTITIES


class ReferenceMonitor:
    policies = POLICIES
    entities = ENTITIES

    def authorize(self, operation, agent, tool):

        request = {
            "principal": f'Agent::"{agent}"',
            "action": f'Action::"{operation.value}"',
            "resource": f'Tool::"{tool}"',
            "context": {
                "data": {
                    "integrity": operation.integrity.value,
                    "source": operation.source,
                }
            },
        }

        print(f"CEDAR REQUEST: {request}")

        response = is_authorized(request, self.policies, self.entities)

        print(f"CEDAR DECISION: {response['decision']}")

        return response["decision"] == "allow"
