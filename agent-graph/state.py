from typing_extensions import TypedDict


class GraphState(TypedDict):
    email: str
    summary: str
    category: str
    crm_operation: str
    customer_id: str
