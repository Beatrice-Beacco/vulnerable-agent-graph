from langgraph.graph import StateGraph
from langgraph.graph import END

from state import GraphState

from agents.triage import create_triage_agent, run_triage_node
from agents.database import create_database_agent, run_database_node
from agents.pii import create_pii_agent, run_pii_node
from agents.intent_analysis import (
    create_intent_analysis_agent,
    run_intent_analysis_agent,
)
from agents.decision import run_decision_node, create_decision_agent
from llm import llm

builder = StateGraph(GraphState)

triage_agent = create_triage_agent(llm)
pii_agent = create_pii_agent(llm)
intent_analysis_agent = create_intent_analysis_agent(llm)
decision_agent = create_decision_agent(llm)
database_agent = create_database_agent(llm)


def triage_node(state):
    state = run_triage_node(state, triage_agent)
    return state


def pii_node(state):
    state = run_pii_node(state, pii_agent)
    return state


def intent_node(state):
    state = run_intent_analysis_agent(state, intent_analysis_agent)
    return state


def decision_node(state):
    state = run_decision_node(state, decision_agent)
    return state


def database_node(state):
    state = run_database_node(state, database_agent)
    return state


builder.add_node("triage", triage_node)
builder.add_node("pii", pii_node)
builder.add_node("intent", intent_node)
builder.add_node("decision", decision_node)
builder.add_node("database", database_node)

builder.set_entry_point("triage")
builder.add_edge("triage", "pii")
builder.add_edge("triage", "intent")
builder.add_edge("pii", "decision")
builder.add_edge("intent", "decision")
builder.add_edge("decision", "database")
builder.add_edge("database", END)

graph = builder.compile()
