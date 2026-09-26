import json

from langchain.tools import tool
from state import Confidentiality

# Classification of every field of a customer record. It is the static label
# of the stored data: it stays sound because the monitor forbids writing data
# of a higher level into a field ("no-write-down-field").
FIELD_CLASSIFICATION = {
    "status": Confidentiality.PUBLIC,
    "name": Confidentiality.INTERNAL,
    "email": Confidentiality.INTERNAL,
    "iban": Confidentiality.CONFIDENTIAL,
    "credit_limit": Confidentiality.CONFIDENTIAL,
}

customers = {
    "7812": {
        "status": "SUSPENDED",
        "name": "Mario Rossi",
        "email": "mario.rossi@example.com",
        "iban": "IT60X0542811101000000123456",
        "credit_limit": "15000",
    }
}


def requested_fields(fields) -> list[str]:
    """
    Normalizes the `fields` argument of read_customer. Shared by the tool and
    the reference monitor, so the fields that are authorized are exactly the
    fields that are returned. "all" (or nothing) means every field.
    """
    if fields is None:
        return list(FIELD_CLASSIFICATION)
    if isinstance(fields, str):
        fields = fields.split(",")
    names = [str(name).strip().strip('"').strip("'").lower() for name in fields]
    names = [name for name in names if name]
    if not names or "all" in names:
        return list(FIELD_CLASSIFICATION)
    return list(dict.fromkeys(names))


@tool
def read_customer(customer_id: str, fields: list[str]) -> str:
    """
    Read fields of a customer record.

    Args:
        customer_id (str): The customer ID.
        fields (list[str]): The fields to read: status, name, email, iban,
            credit_limit, or ["all"]. Read only the fields you need.
    """
    record = customers.get(str(customer_id))
    if record is None:
        return json.dumps({"error": f"customer {customer_id} not found"})

    return json.dumps(
        {name: record.get(name) for name in requested_fields(fields)}
    )


@tool
def write_customer(customer_id: str, field: str, value: str) -> str:
    """
    Update one field of a customer record.

    Use this tool when the requested operation is update_customer.
    """
    record = customers.setdefault(str(customer_id), {})
    record[field] = value
    print(f"[DB] Updated {customer_id}.{field}")
    return f"customer {customer_id} updated"


@tool
def delete_customer(customer_id: str) -> str:
    """
    Delete a customer record.
    Use this tool when the requested operation is delete_customer.
    """
    if str(customer_id) in customers:
        del customers[str(customer_id)]
        print(f"[DB] Customer {customer_id} deleted.")
        return f"customer {customer_id} deleted"

    print("[DB] Customer not found.")
    return f"customer {customer_id} not found"
