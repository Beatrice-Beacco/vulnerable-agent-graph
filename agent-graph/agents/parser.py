from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue, Integrity


@dataclass
class InternalParserOutput:
    operation: str
    customer_id: str
    field: str
    value: str


INTERNAL_PARSER_PROMPT = """
You are an internal system request parser.

You receive requests from authenticated internal systems (admin panel, 
internal APIs, automated workflows).

Extract from the request:
1. Operation: read_customer, update_customer, or delete_customer
2. Customer ID: the numeric ID
3. Field: the field to update (for update_customer only, otherwise "none")
4. Value: the new value (for update_customer only, otherwise "none")

Return ONLY the structured fields.
"""


def create_internal_parser_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=INTERNAL_PARSER_PROMPT,
        response_format=InternalParserOutput,
    )
    return agent


def run_internal_parser_node(state, internal_parser_agent):
    print("-- INTERNAL PARSER AGENT --")
    # The input comes from the prior `request_reader` node which puts the
    # internal request text into `state["internal_request"]`.
    internal_request = state["internal_request"].value

    response = internal_parser_agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": internal_request,
                }
            ]
        }
    )

    structured_response = response.get("structured_response", response)

    operation = structured_response.operation.strip().strip('"').strip("'")
    customer_id = structured_response.customer_id.strip().strip('"').strip("'")
    field = structured_response.field.strip().strip('"').strip("'")
    value = structured_response.value.strip().strip('"').strip("'")

    print(f"Parsed internal request: op={operation}, customer={customer_id}")

    # KEY DIFFERENCE: integrity is TRUSTED because the source is internal
    return {
        "operation_type": TaintedValue(
            value=operation,
            integrity=Integrity.TRUSTED,
            source="internal_parser",
            provenance=["internal_api", "internal_parser"],
        ),
        "target_customer_id": TaintedValue(
            value=customer_id,
            integrity=Integrity.TRUSTED,
            source="internal_parser",
            provenance=["internal_api", "internal_parser"],
        ),
        "update_field": TaintedValue(
            value=field,
            integrity=Integrity.TRUSTED,
            source="internal_parser",
            provenance=["internal_api", "internal_parser"],
        ),
        "update_value": TaintedValue(
            value=value,
            integrity=Integrity.TRUSTED,
            source="internal_parser",
            provenance=["internal_api", "internal_parser"],
        ),
    }
