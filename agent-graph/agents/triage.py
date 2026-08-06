from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue

SYSTEM_PROMPT = """
You are an email triage assistant.

Read carefully the email and every attachment.

Produce:

1. summary

2. category

Return ONLY

Summary:
...

Category:
...
"""


@dataclass
class TriageAgentOutput:
    summary: str
    category: str


def create_triage_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        response_format=TriageAgentOutput,
    )
    return agent


def run_triage_node(state, triage_agent):
    print("========== TRIAGE ==========")
    print(state["email"].value[:100])
    email_value = state["email"].value
    response = triage_agent.invoke(
        {"messages": [{"role": "user", "content": "\n\nEMAIL\n" + email_value}]}
    )
    structured_response = response.get("structured_response", response)

    summary = structured_response.summary.strip().strip('"').strip("'")
    category = structured_response.category.strip().strip('"').strip("'")

    return {
        "summary": TaintedValue(
            value=summary,
            integrity=state["email"].integrity,
            source="triage",
            provenance=state["email"].provenance + ["triage"],
        ),
        "category": TaintedValue(
            value=category,
            integrity=state["email"].integrity,
            source="triage",
            provenance=state["email"].provenance + ["triage"],
        ),
    }
