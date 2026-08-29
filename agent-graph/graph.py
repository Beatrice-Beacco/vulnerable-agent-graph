from langgraph.graph import StateGraph
from langgraph.graph import END
from langgraph_sdk.schema import Command

from state import GraphState

from agents.triage import create_triage_agent, run_triage_node
from agents.database import create_database_agent, run_database_node
from agents.router import create_router_agent, run_router_node
from agents.email import create_read_email_agent, run_read_email_node
from agents.request_reader import create_request_reader_agent, run_request_reader_node
from agents.parser import create_internal_parser_agent, run_internal_parser_node
from llm import llm

builder = StateGraph(GraphState)

router_agent = create_router_agent(llm)
email_agent = create_read_email_agent(llm)
triage_agent = create_triage_agent(llm)
database_agent = create_database_agent(llm)
request_reader_agent = create_request_reader_agent(llm)
parser_agent = create_internal_parser_agent(llm)


def router_node(state):
    result = run_router_node(state, router_agent)
    return result


def read_email_node(state):
    state = run_read_email_node(state, email_agent)
    return state


def triage_node(state):
    state = run_triage_node(state, triage_agent)
    return state


def request_reader_node(state):
    state = run_request_reader_node(state, request_reader_agent)
    return state


def parser_node(state):
    state = run_internal_parser_node(state, parser_agent)
    return state


def database_node(state):
    state = run_database_node(state, database_agent)
    return state


def route_to_branch(state):
    """
    Reads selected_branch from state and returns the next node name.
    Must return a string that matches an existing node name.
    """
    selected = state["selected_branch"].value

    print(f"Router decision: {selected}")

    if selected == "customer_support":
        return "read_email"
    elif selected == "internal_ops":
        return "request_reader"
    else:
        return "read_email"  # fallback


builder.add_node("router", router_node)
builder.add_node("read_email", read_email_node)
builder.add_node("triage", triage_node)
builder.add_node("database", database_node)
builder.add_node("request_reader", request_reader_node)
builder.add_node("parser", parser_node)

builder.set_entry_point("router")

# Conditional routing: router -> one of the two branches
builder.add_conditional_edges(
    "router",  # source node
    route_to_branch,  # routing function
    {  # mapping: return value -> node name
        "read_email": "read_email",
        "request_reader": "request_reader",
    },
)


# Branch 1
builder.add_edge("read_email", "triage")
builder.add_edge("triage", "database")
# Branch 2
builder.add_edge("request_reader", "parser")
builder.add_edge("parser", "database")

builder.add_edge("database", END)

graph = builder.compile()
