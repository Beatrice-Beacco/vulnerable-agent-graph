from tools.crm import write_customer
from tools.crm import delete_customer
from utils.exceptions import SecurityException
from state import Integrity


def database(state):

    operation = state["crm_operation"]
    customer = state["customer_id"]
    operation_value = operation.value
    customer_value = customer.value

    if operation.integrity == Integrity.UNTRUSTED:
        raise SecurityException()

    print()
    print("DATABASE AGENT")
    print("----------------")
    print(state)
    print()

    if operation_value == "delete_customer":
        delete_customer(customer_value)
    elif operation_value == "update_customer":
        write_customer(customer_value, "UPDATED")
    else:
        print("No operation.")

    return {}
