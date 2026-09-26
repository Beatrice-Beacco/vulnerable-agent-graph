from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue


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


def create_internal_parser_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=INTERNAL_PARSER_PROMPT,
        response_format=InternalParserOutput,
    )
    return agent


def _clean(text: str) -> str:
    return text.strip().strip('"').strip("'")


def run_internal_parser_node(state, internal_parser_agent):
    print("-- INTERNAL PARSER AGENT --")
    # The input comes from the prior `request_reader` node which puts the
    # internal request text into `state["internal_request"]`.
    internal_request = state["internal_request"]

    response = internal_parser_agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": internal_request.value,
                }
            ]
        }
    )

    structured_response = response.get("structured_response", response)

    output = {
        "operation_type": _clean(structured_response.operation),
        "target_customer_id": _clean(structured_response.customer_id),
        "update_field": _clean(structured_response.field),
        "update_value": _clean(structured_response.value),
        "recipient": _clean(structured_response.recipient),
    }

    print(f"Parsed internal request: {output}")

    # The output is derived from the internal request only: it inherits its
    # label (TRUSTED, since the source is internal).
    return {
        name: TaintedValue(
            value=value,
            integrity=internal_request.integrity,
            confidentiality=internal_request.confidentiality,
            source="internal_parser",
            provenance=internal_request.provenance + ["internal_parser"],
        )
        for name, value in output.items()
    }
