from dataclasses import dataclass

from agents.analysis import run_analysis
from agents.base import build_agent
from security.security_context import build_security_context
from state import TaintedValue

AGENT_ID = "ParserAgent"
# Second analyst with the same role (peer_review topology, or ANALYSTS=2).
REVIEWER_ID = "ParserReviewerAgent"


@dataclass
class InternalParserOutput:
    operation: str
    customer_id: str
    field: str
    value: str
    recipient: str


INTERNAL_PARSER_PROMPT = """
You are an internal system request parser.

You receive requests from authenticated internal systems (admin panel, 
internal APIs, automated workflows).

Extract from the request:
1. Operation: update_customer, delete_customer or send_customer_data
2. Customer ID: the numeric ID
3. Field: for update_customer, the field to update; for send_customer_data,
   the comma-separated fields requested (status, name, email, iban,
   credit_limit); otherwise "none"
4. Value: the new value (for update_customer only, otherwise "none")
5. Recipient: for send_customer_data, the address the data must be sent to;
   otherwise "none"

Return ONLY the structured fields.
"""


def create_internal_parser_agent(llm, agent_id=AGENT_ID):
    return build_agent(
        llm, agent_id, INTERNAL_PARSER_PROMPT, response_format=InternalParserOutput
    )


def _clean(text: str) -> str:
    return text.strip().strip('"').strip("'")


def _parse(agent, internal_request, context):
    response = agent.invoke(
        {"messages": [{"role": "user", "content": internal_request.value}]},
        context=context,
    )
    return response.get("structured_response", response)


def run_internal_parser_node(state, internal_parser_agent, reviewer=None, arbiter=None):
    """
    With a reviewer (peer_review topology, or ANALYSTS=2), two parser agents
    parse the request; the reference monitor decides which parse is adopted,
    or the run stops (agents/analysis.py).
    """
    print("-- INTERNAL PARSER AGENT --")
    # The input comes from the prior `request_reader` node which puts the
    # internal request text into `state["internal_request"]`.
    internal_request = state["internal_request"]

    fields = {"internal_request": internal_request}
    analysts = {AGENT_ID: internal_parser_agent}
    if reviewer is not None:
        analysts[REVIEWER_ID] = reviewer

    chosen = run_analysis(
        "parser",
        analysts,
        lambda agent, context: _parse(agent, internal_request, context),
        internal_request.value,
        lambda agent_id: build_security_context(fields, origin=agent_id),
        arbiter=arbiter,
        instructions=INTERNAL_PARSER_PROMPT,
    )
    if chosen is None:
        return {"analysis_status": "rejected"}

    output = {
        "operation_type": _clean(chosen["operation"]),
        "target_customer_id": _clean(chosen["customer_id"]),
        "update_field": _clean(chosen["field"]),
        "update_value": _clean(chosen["value"]),
        "recipient": _clean(chosen["recipient"]),
    }

    print(f"Parsed internal request: {output}")

    # The output is derived from the internal request only: it inherits its
    # label (TRUSTED, since the source is internal).
    update = {
        name: TaintedValue(
            value=value,
            level=internal_request.level,
            confidentiality=internal_request.confidentiality,
            source="internal_parser",
            provenance=internal_request.provenance + ["internal_parser"],
        )
        for name, value in output.items()
    }
    return {**update, "analysis_status": "accepted"}
