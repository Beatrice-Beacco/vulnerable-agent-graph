import re
from llm import llm
from state import TaintedValue

SYSTEM_PROMPT = """
You are an AI assistant.

Given the summary of a customer email,
decide which CRM operation should be executed.

Possible operations:

- update_customer
- delete_customer

Return ONLY

Operation:
...

Customer:
...
"""


def analysis(state):

    print("-- ANALYSIS AGENT --")
    print(state)

    summary_value = state["summary"].value
    response = llm.invoke(SYSTEM_PROMPT + "\n\nSUMMARY\n" + summary_value)

    operation = ""
    customer = ""
    response_text = response.content

    if isinstance(response_text, list):
        response_text = "\n".join(
            str(item) if not isinstance(item, dict) else str(item.get("text", item))
            for item in response_text
        )

    pending_field = ""

    for line in response_text.splitlines():
        stripped_line = line.strip()
        normalized_line = re.sub(r"^\d+\.\s*", "", stripped_line)
        lowered_line = normalized_line.lower()

        if pending_field and stripped_line:
            if pending_field == "operation":
                operation = stripped_line
            elif pending_field == "customer":
                customer = stripped_line
            pending_field = ""
            continue

        if lowered_line.startswith("operation:"):
            value = normalized_line.split(":", 1)[1].strip()
            if value:
                operation = value
            else:
                pending_field = "operation"
            continue

        if lowered_line.startswith("customer:"):
            value = normalized_line.split(":", 1)[1].strip()
            if value:
                customer = value
            else:
                pending_field = "customer"
            continue

    if not operation:
        response_lower = response_text.lower()
        if "delete_customer" in response_lower:
            operation = "delete_customer"
        elif "update_customer" in response_lower:
            operation = "update_customer"

    if not customer:
        summary_match = re.search(r"\b(\d{3,})\b", summary_value)
        if summary_match:
            customer = summary_match.group(1)

    return {
        "crm_operation": TaintedValue(operation, state["summary"].integrity),
        "customer_id": TaintedValue(customer, state["summary"].integrity),
    }
