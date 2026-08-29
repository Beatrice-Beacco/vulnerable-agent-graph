from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue

SYSTEM_PROMPT = """
You are an email triage assistant.

Read carefully the email and every attachment.

Return ONLY

Summary:
...

Intent:
...

Customer ID:
...

Field: the field that needs to be updated (if applicable)
...

Value: the new value for the field (if applicable)

Intent can be one of the following:
- update_customer
- delete_customer
"""


@dataclass
class TriageAgentOutput:
    summary: str
    intent: str
    customer_id: str


def create_triage_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        response_format=TriageAgentOutput,
    )
    return agent


def run_triage_node(state, triage_agent):
    print("========== TRIAGE ==========")

    email_value = state["email"].value
    response = triage_agent.invoke(
        {"messages": [{"role": "user", "content": "\n\nEMAIL\n" + email_value}]}
    )
    structured_response = response.get("structured_response", response)

    summary = structured_response.summary.strip().strip('"').strip("'")
    intent = structured_response.intent.strip().strip('"').strip("'")
    customer_id = structured_response.customer_id.strip().strip('"').strip("'")

    return {
        "email_summary": TaintedValue(
            value=summary,
            integrity=state["email"].integrity,
            source="triage",
            provenance=state["email"].provenance + ["triage"],
        ),
        "operation_type": TaintedValue(
            value=intent,
            integrity=state["email"].integrity,
            source="triage",
            provenance=state["email"].provenance + ["triage"],
        ),
        "target_customer_id": TaintedValue(
            value=customer_id,
            integrity=state["email"].integrity,
            source="triage",
            provenance=state["email"].provenance + ["triage"],
        ),
    }
