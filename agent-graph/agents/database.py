from tools.crm import write_customer
from tools.crm import delete_customer
from cedar.engine import ReferenceMonitor

monitor = ReferenceMonitor()


def database(state):

    operation = state["crm_operation"]
    customer = state["customer_id"]

    operation_value = operation.value.strip() if operation.value else ""
    customer_value = customer.value.strip() if customer.value else ""

    if not operation_value:
        print("NO CRM OPERATION PROVIDED")
        return {}

    allowed = monitor.authorize(
        operation=operation, agent="DatabaseAgent", tool="CRMDatabase"
    )

    if not allowed:
        print("BLOCKED BY CEDAR")
        return {}

    if operation_value == "delete_customer":
        delete_customer(customer_value)

    if operation_value == "update_customer":
        write_customer(customer_id=customer_value, status="updated")
