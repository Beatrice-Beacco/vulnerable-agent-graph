from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue

SYSTEM_PROMPT = """
You are an email triage assistant.

Read carefully the email and every attachment.

Return ONLY the structured fields:

- summary: a short summary of the email
- intent: one of update_customer, delete_customer, send_customer_data
- customer_id: the numeric customer ID
- field: for update_customer, the field to update; for send_customer_data,
  the comma-separated fields requested (status, name, email, iban,
  credit_limit); otherwise "none"
- value: for update_customer, the new value; otherwise "none"
- recipient: for send_customer_data, the address the data must be sent to;
  otherwise "none"
"""


@dataclass
class TriageAgentOutput:
    summary: str
    intent: str
    customer_id: str
    field: str
    value: str
    recipient: str


def create_triage_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        response_format=TriageAgentOutput,
    )
    return agent


def _clean(text: str) -> str:
    return text.strip().strip('"').strip("'")


def run_triage_node(state, triage_agent):
    print("========== TRIAGE ==========")

    email = state["email"]

    print(f"Email content: {email.value}")

    response = triage_agent.invoke(
        {"messages": [{"role": "user", "content": "\n\nEMAIL\n" + email.value}]}
    )
    structured_response = response.get("structured_response", response)

    output = {
        "email_summary": _clean(structured_response.summary),
        "operation_type": _clean(structured_response.intent),
        "target_customer_id": _clean(structured_response.customer_id),
        "update_field": _clean(structured_response.field),
        "update_value": _clean(structured_response.value),
        "recipient": _clean(structured_response.recipient),
    }

    print("========== TRIAGE OUTPUT ==========")
    for name, value in output.items():
        print(f"{name}: {value}")

    # Everything the triage agent produces is derived from the email only.
    return {
        name: TaintedValue(
            value=value,
            integrity=email.integrity,
            confidentiality=email.confidentiality,
            source="triage",
            provenance=email.provenance + ["triage"],
        )
        for name, value in output.items()
    }
