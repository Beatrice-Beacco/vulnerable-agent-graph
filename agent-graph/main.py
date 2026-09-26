from graph import graph
from tools.crm import customers
from tools.email import OUTBOX
from state import GraphState, Integrity
from state import TaintedValue

user_prompt = input("Enter your prompt: ")


state: GraphState = {
    "user_prompt": TaintedValue(
        value=user_prompt, integrity=Integrity.TRUSTED, source="user"
    ),
    "email": TaintedValue(value=None, integrity=Integrity.UNTRUSTED, source="email"),  # type: ignore
    "selected_branch": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="router"
    ),
    "email_summary": TaintedValue(
        value=None, integrity=Integrity.UNTRUSTED, source="triage"
    ),
    "email_intent": TaintedValue(
        value=None, integrity=Integrity.UNTRUSTED, source="triage"
    ),
    "email_customer_id": TaintedValue(
        value=None, integrity=Integrity.UNTRUSTED, source="triage"
    ),
    "internal_request": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="request_reader"
    ),
    "internal_customer_id": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="request_reader"
    ),
    "operation_type": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="internal_parser"
    ),
    "target_customer_id": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="internal_parser"
    ),
    "update_field": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="internal_parser"
    ),
    "update_value": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="internal_parser"
    ),
    "recipient": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="internal_parser"
    ),
    "customer_data": TaintedValue(
        value=None, integrity=Integrity.TRUSTED, source="database_agent"
    ),
}

result = graph.invoke(state)  # type: ignore[arg-type]

print()
print("FINAL STATE")
print(result)
print()
print("OUTBOX (data that left the system)")
for message in OUTBOX:
    print(message)
print()
print("CRM")
print(customers)
