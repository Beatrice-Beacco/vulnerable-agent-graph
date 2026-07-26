from tools.crm import write_customer
from tools.crm import delete_customer


def database(state):

    operation = state["crm_operation"]
    customer = state["customer_id"]

    print()
    print("DATABASE AGENT")
    print("----------------")
    print(state)
    print()

    if operation == "delete_customer":
        delete_customer(customer)
    elif operation == "update_customer":
        write_customer(customer, "UPDATED")
    else:
        print("No operation.")

    return {}
