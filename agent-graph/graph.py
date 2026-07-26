from langgraph.graph import StateGraph
from langgraph.graph import END

from state import GraphState

from agents.triage import triage
from agents.analysis import analysis
from agents.database import database

builder = StateGraph(GraphState)

builder.add_node("triage", triage)
builder.add_node("analysis", analysis)
builder.add_node("database", database)
builder.set_entry_point("triage")
builder.add_edge("triage", "analysis")
builder.add_edge("analysis", "database")
builder.add_edge("database", END)

graph = builder.compile()
