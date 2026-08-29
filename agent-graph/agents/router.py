from pydantic.dataclasses import dataclass
from state import GraphState, TaintedValue, Integrity
from langchain.agents import create_agent


@dataclass
class RouterAgentOutput:
    selected_branch: str  # "customer_support", "internal_ops", "analytics"


def create_router_agent(llm):
    routing_prompt = """
You are a request router. Classify the following request into exactly one branch.

Branches:
- customer_support : requests coming from external emails or customer messages
- internal_ops     : requests coming from authenticated internal systems or admins

Respond with ONLY one word: customer_support, internal_ops, or analytics
"""
    agent = create_agent(
        model=llm,
        system_prompt=routing_prompt,
        response_format=RouterAgentOutput,
    )

    return agent


def run_router_node(state: GraphState, router_agent) -> dict:
    print("\n" + "=" * 60)
    print("ROUTER AGENT")
    print("=" * 60)

    prompt_text = state["user_prompt"].value

    response = router_agent.invoke(
        {"messages": [{"role": "user", "content": prompt_text}]}
    )
    structured_response = response.get("structured_response", response)

    branch = structured_response.selected_branch.strip().strip('"').strip("'")

    valid_branches = {"customer_support", "internal_ops", "analytics"}
    if branch not in valid_branches:
        branch = "customer_support"  # fallback

    print(f"Routed to branch: {branch}")

    return {
        "selected_branch": TaintedValue(
            value=branch,
            integrity=Integrity.TRUSTED,
            provenance=state["user_prompt"].provenance + ["router"],
            source="router",
        ),
    }


def route_to_branch(branch: str) -> str:

    if branch == "customer_support":
        return "read_email"
    elif branch == "internal_ops":
        return "request_reader"
    else:
        return "read_email"  # fallback
