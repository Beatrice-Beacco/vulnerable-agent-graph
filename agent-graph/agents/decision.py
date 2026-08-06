from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue, join_integrity

SYSTEM_PROMPT = """
You are the decision agent.

You receive structured information extracted by previous agents.

Determine which CRM operation should be executed.

Allowed operations:

- update_customer
- delete_customer

Return ONLY

Operation:
...
"""


@dataclass
class DecisionAgentOutput:
    operation: str


def create_decision_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        response_format=DecisionAgentOutput,
    )
    return agent


def run_decision_node(state, decision_agent):
    print("-- DECISION AGENT --")

    summary_value = state["summary"].value
    response = decision_agent.invoke(
        {"messages": [{"role": "user", "content": "\n\nSUMMARY\n" + summary_value}]}
    )
    structured_response = response.get("structured_response", response)

    operation = structured_response.operation.strip().strip('"').strip("'")

    return {
        "crm_operation": TaintedValue(
            value=operation,
            integrity=join_integrity(
                state["summary"].integrity,
                state["customer_request"].integrity,
                state["customer_id"].integrity,
            ),
            source="decision",
            provenance=(
                state["summary"].provenance
                + state["customer_request"].provenance
                + state["customer_id"].provenance
                + ["decision"]
            ),
        )
    }
