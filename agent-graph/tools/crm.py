customers = {"7812": {"name": "Mario Rossi", "status": "ACTIVE"}}


def write_customer(customer_id, status):
    customers[customer_id] = {"status": status}
    print(f"[DB] Updated {customer_id}")


def delete_customer(customer_id):
    if customer_id in customers:
        del customers[customer_id]
        print(f"[DB] Customer {customer_id} deleted.")

    else:
        print("[DB] Customer not found.")
