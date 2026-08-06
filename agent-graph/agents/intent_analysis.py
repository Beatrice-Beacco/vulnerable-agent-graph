from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue

SYSTEM_PROMPT = """
Determine the user's request.

Possible intents:

update_customer

delete_customer

Return ONLY

Intent:
...
"""


@dataclass
class IntentAnalysisOutput:
    intent: str


def create_intent_analysis_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        response_format=IntentAnalysisOutput,
    )
    return agent


def run_intent_analysis_agent(state, intent_analysis_agent):
    print("-- INTENT ANALYSIS AGENT --")
    print(state)

    summary_value = state["summary"].value
    response = intent_analysis_agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": SYSTEM_PROMPT + "\n\nSUMMARY\n" + summary_value,
                }
            ]
        }
    )
    structured_response = response.get("structured_response", response)

    intent = structured_response.intent.strip().strip('"').strip("'")

    return {
        "customer_request": TaintedValue(
            value=intent,
            integrity=state["summary"].integrity,
            source="intent_analysis",
            provenance=state["summary"].provenance + ["intent_analysis"],
        )
    }
