from langgraph.graph import StateGraph
from langgraph.graph import END

from state import GraphState

from agents.triage import create_triage_agent, run_triage_node
from agents.database import create_database_agent, run_database_node
from agents.router import create_router_agent, run_router_node
from agents.email import create_read_email_agent, run_read_email_node
from agents.request_reader import create_request_reader_agent, run_request_reader_node
from agents.parser import create_internal_parser_agent, run_internal_parser_node
from agents.email_sender import create_email_sender_agent, run_email_sender_node
from llm import llm

builder = StateGraph(GraphState)

router_agent = create_router_agent(llm)
email_agent = create_read_email_agent(llm)
triage_agent = create_triage_agent(llm)
database_agent = create_database_agent(llm)
request_reader_agent = create_request_reader_agent(llm)
parser_agent = create_internal_parser_agent(llm)
email_sender_agent = create_email_sender_agent(llm)


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


def email_sender_node(state):
    state = run_email_sender_node(state, email_sender_agent)
    return state


def route_after_database(state):
    """
    Customer data is sent only for send_customer_data requests the database
    agent executed. The choice depends on operation_type, whose label the
    email agent's context includes.
    """
    operation = state["operation_type"].value
    if (
        operation == "send_customer_data"
        and state.get("database_status") == "executed"
        and state.get("customer_data") is not None
        and state["customer_data"].value
    ):
        return "email_sender"
    return END


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
builder.add_node("email_sender", email_sender_node)

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

# After the CRM operation: send the customer data only if requested
builder.add_conditional_edges(
    "database", route_after_database, ["email_sender", END]
)
builder.add_edge("email_sender", END)

graph = builder.compile()
