from dataclasses import dataclass

from agents.analysis import run_analysis
from agents.base import build_agent
from security.security_context import build_security_context
from state import TaintedValue

AGENT_ID = "TriageAgent"
# Second analyst with the same role (peer_review topology, or ANALYSTS=2).
REVIEWER_ID = "TriageReviewerAgent"

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


def create_triage_agent(llm, agent_id=AGENT_ID):
    return build_agent(llm, agent_id, SYSTEM_PROMPT, response_format=TriageAgentOutput)


def _clean(text: str) -> str:
    return text.strip().strip('"').strip("'")


def _analyze(agent, email, context):
    response = agent.invoke(
        {"messages": [{"role": "user", "content": "\n\nEMAIL\n" + email.value}]},
        context=context,
    )
    return response.get("structured_response", response)


def run_triage_node(state, triage_agent, reviewer=None, arbiter=None):
    """
    With a reviewer (peer_review topology, or ANALYSTS=2), two triage agents
    analyze the email; the reference monitor decides which analysis is
    adopted, or the run stops (agents/analysis.py).
    """
    print("========== TRIAGE ==========")

    email = state["email"]

    print(f"Email content: {email.value}")

    fields = {"email": email}
    analysts = {AGENT_ID: triage_agent}
    if reviewer is not None:
        analysts[REVIEWER_ID] = reviewer

    chosen = run_analysis(
        "triage",
        analysts,
        lambda agent, context: _analyze(agent, email, context),
        email.value,
        lambda agent_id: build_security_context(fields, origin=agent_id),
        arbiter=arbiter,
        instructions=SYSTEM_PROMPT,
    )
    if chosen is None:
        return {"analysis_status": "rejected"}

    output = {
        "email_summary": _clean(chosen["summary"]),
        "operation_type": _clean(chosen["intent"]),
        "target_customer_id": _clean(chosen["customer_id"]),
        "update_field": _clean(chosen["field"]),
        "update_value": _clean(chosen["value"]),
        "recipient": _clean(chosen["recipient"]),
    }

    print("========== TRIAGE OUTPUT ==========")
    for name, value in output.items():
        print(f"{name}: {value}")

    # Everything the triage agent produces is derived from the email only.
    update = {
        name: TaintedValue(
            value=value,
            integrity=email.integrity,
            confidentiality=email.confidentiality,
            source="triage",
            provenance=email.provenance + ["triage"],
        )
        for name, value in output.items()
    }
    return {**update, "analysis_status": "accepted"}
