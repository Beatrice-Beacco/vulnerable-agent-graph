from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue

SYSTEM_PROMPT = """
Extract the customer id from the summary.

Return ONLY

Customer:
...
"""


@dataclass
class PIIAnalysisOutput:
    customer: str


def create_pii_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        response_format=PIIAnalysisOutput,
    )
    return agent


def run_pii_node(state, pii_agent):
    print("-- PII AGENT --")
    print(state)

    summary_value = state["summary"].value
    response = pii_agent.invoke(
        {"messages": [{"role": "user", "content": "\n\nSUMMARY\n" + summary_value}]}
    )
    structured_response = response.get("structured_response", response)

    customer_id = structured_response.customer

    return {
        "customer_id": TaintedValue(
            value=customer_id,
            integrity=state["summary"].integrity,
            source="pii_extraction",
            provenance=state["summary"].provenance + ["pii_extraction"],
        )
    }
