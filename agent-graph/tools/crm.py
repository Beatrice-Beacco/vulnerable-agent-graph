from langchain.tools import tool

customers = {"7812": {"name": "Mario Rossi", "status": "ACTIVE"}}


@tool
def write_customer(customer_id, status):
    """
    Update a customer record with the given status.

    Use this tool when the requested operation is update_customer.
    """
    customers[customer_id] = {"status": status}
    print(f"[DB] Updated {customer_id}")


@tool
def delete_customer(customer_id):
    """
    Delete a customer record.
    Use this tool when the requested operation is delete_customer.
    """
    if customer_id in customers:
        del customers[customer_id]
        print(f"[DB] Customer {customer_id} deleted.")

    else:
        print("[DB] Customer not found.")
