"""
Builds a team `SystemSpec` into a LangGraph `StateGraph`, with the project's
reference monitor on every agent. One node per agent, wired as the spec's
topology (round_robin / supervisor / swarm). Each node runs a monitored agent
(systems/agent.build_monitored_agent: the Cedar PEP on its tools).

Labels travel the project's way, not as one shared mutable label: the shared
conversation is a list of `TaintedValue` contributions (the user query, then
each agent's reply). An agent's turn builds its `SecurityContext` from all
contributions so far (so a low-trust read by an earlier agent lowers this
agent's level, the meet); the PEP mediates the agent's tool calls and absorbs
each read's label; the agent's reply is labeled with its resulting context and
appended. The LLM sees the plain text; the labels ride alongside in the state.

This is what lets a data-defined system (a benchmark instance) run on the
project's single reference monitor.
"""

import operator
import os
from typing import Annotated, Callable, TypedDict, cast

from langchain.messages import AIMessage
from langgraph.errors import GraphRecursionError
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from systems.agent import build_monitored_agent
from security.security_context import build_security_context
from security.trace import event
from state import Level, TaintedValue
from engine.system import SystemSpec

# Graph steps per agent turn (a tool call is two): bounds a looping turn.
RECURSION_LIMIT = int(os.getenv("TEAM_RECURSION_LIMIT", "40"))

SUPERVISOR = "supervisor"
TEAM_TOPOLOGIES = ("round_robin", "supervisor", "swarm")

# A tool resolver maps a provisioned tool name to the tool object the agent calls.
ToolResolver = Callable[[str], object]


class TeamState(TypedDict):
    messages: Annotated[list, operator.add]           # plain text, for the LLM
    contributions: Annotated[list, operator.add]      # TaintedValue per turn, for labels
    turns: int
    unvisited: list[str]
    next: str
    denied: dict                                      # agent -> denied calls so far (quarantine)


def _agent_tools(spec_agent, resolver: ToolResolver) -> list:
    # The LLM is given every tool the agent is built with (provisioned +
    # ungranted/attacker); the monitor's grant denies the ungranted ones.
    return [resolver(name) for name in spec_agent.built_tools()]


def _context(name: str, contributions: list, denied: int):
    """The agent's SecurityContext: the join of every contribution so far
    (meet of levels), built the project way from labeled fields, seeded with
    how many of this agent's calls the monitor has already denied this run
    (so quarantine persists across its turns)."""
    fields = {f"turn_{i}": tv for i, tv in enumerate(contributions)}
    context = build_security_context(fields, origin=name)
    context.denied_calls = denied
    return context


def _turn(name: str, agent, state: TeamState) -> dict:
    """Run one agent behind the PEP; return its reply (text + TaintedValue) and
    the agent's denied-call count. A hard deny (PermissionError) ends the turn,
    as a CRM node catches it."""
    print(f"\n-- {name} --")
    context = _context(name, state["contributions"], state["denied"].get(name, 0))
    n_in = len(state["messages"])
    try:
        result = agent.invoke(
            {"messages": state["messages"]},
            context=context,
            config={"recursion_limit": RECURSION_LIMIT},
        )
        new = result["messages"][n_in:]
        text = next((m.text for m in reversed(new) if isinstance(m, AIMessage) and m.text), "")
    except PermissionError as exc:
        event("turn_stopped", agent=name, reason=str(exc))
        text = "(stopped by the security monitor)"
    except GraphRecursionError:
        event("turn_stopped", agent=name, reason="recursion limit")
        text = "(turn cut off: step limit)"
    labeled = context.labeled(f"[{name}] {text}", source=name)
    return {"role": "user", "content": labeled.value, "tainted": labeled,
            "denied": context.denied_calls}


def _acted(state: TeamState, name: str, reply: dict) -> dict:
    return {
        "messages": [{"role": "user", "content": reply["content"]}],
        "contributions": [reply["tainted"]],
        "turns": state["turns"] + 1,
        "unvisited": [n for n in state["unvisited"] if n != name],
        "denied": {**state["denied"], name: reply["denied"]},
    }


def _terminated(state: TeamState) -> bool:
    return "TERMINATE" in str(state["messages"][-1]["content"])


def _route(roster, llm, messages, unvisited) -> str:
    """LLM picks the next speaker (or TERMINATE), preferring an agent that has
    not acted; falls back so routing is robust and every agent gets a turn."""
    names = [n for n, _ in roster]
    if unvisited:
        allowed = [n for n in names if n in unvisited]
        hint = "You must still involve: " + ", ".join(allowed) + "."
        terminate_ok = False
    else:
        allowed, hint, terminate_ok = names, "Every agent has acted; reply TERMINATE if done.", True
    roster_txt = "\n".join(f"- {n}: {d.splitlines()[0][:120]}" for n, d in roster)
    tail = "\n".join(str(m.get("content", ""))[:400] for m in messages[-4:])
    prompt = (
        "You orchestrate a team working on the user's task.\n"
        f"Agents:\n{roster_txt}\n\nRecent conversation:\n{tail}\n\n{hint}\n"
        "Reply with ONLY the exact name of the next agent to act"
        + (", or TERMINATE." if terminate_ok else ".")
    )
    try:
        reply = str(getattr(llm.invoke(prompt), "content", "") or "")
    except Exception:  # noqa: BLE001 -- routing must not crash the run
        reply = ""
    if terminate_ok and "TERMINATE" in reply.upper():
        return "TERMINATE"
    for n in allowed:
        if n.lower() in reply.lower():
            return n
    return allowed[0]


def build_team_graph(spec: SystemSpec, llm, resolver: ToolResolver, max_rounds: int = 2, monitor=None):
    """Compile the team graph; returns (graph, turn budget). `monitor` is the
    system's reference monitor (engine/monitors.build_team_monitor)."""
    if spec.topology not in TEAM_TOPOLOGIES:
        raise ValueError(f"{spec.topology!r} is not a team topology {TEAM_TOPOLOGIES}")
    names = [a.id for a in spec.agents]
    if len(set(names)) != len(names) or SUPERVISOR in names:
        raise ValueError(f"agent ids must be unique and not {SUPERVISOR!r}: {names}")
    agents = {
        a.id: build_monitored_agent(llm, a.id, a.prompt, _agent_tools(a, resolver), monitor=monitor)
        for a in spec.agents
    }
    roster = [(a.id, a.prompt) for a in spec.agents]
    budget = max_rounds * len(names)

    def node(name):
        return lambda state: _acted(state, name, _turn(name, agents[name], state))

    graph = StateGraph(TeamState)

    if spec.topology == "round_robin":
        for name in names:
            graph.add_node(name, node(name))
        graph.add_edge(START, names[0])
        for i, name in enumerate(names):
            following = names[(i + 1) % len(names)]
            graph.add_conditional_edges(
                name,
                lambda s, following=following: END
                if _terminated(s) or s["turns"] >= budget else following,
                [following, END],
            )

    elif spec.topology == "supervisor":
        def supervisor(state: TeamState) -> dict:
            if state["turns"] >= budget:
                return {"next": "TERMINATE"}
            pick = _route(roster, llm, state["messages"], set(state["unvisited"]))
            if pick != "TERMINATE":
                event("route", topology="supervisor", next=pick)
            return {"next": pick}

        graph.add_node(SUPERVISOR, supervisor)
        graph.add_edge(START, SUPERVISOR)
        graph.add_conditional_edges(
            SUPERVISOR, lambda s: END if s["next"] == "TERMINATE" else s["next"], [*names, END]
        )
        for name in names:
            graph.add_node(name, node(name))
            graph.add_conditional_edges(
                name,
                lambda s: END if not s["unvisited"] and _terminated(s) else SUPERVISOR,
                [SUPERVISOR, END],
            )

    else:  # swarm
        def swarm_node(name):
            def handoff(state: TeamState) -> Command:
                reply = _turn(name, agents[name], state)
                update = _acted(state, name, reply)
                done = update["turns"] >= budget or (
                    not update["unvisited"] and "TERMINATE" in reply["content"]
                )
                if done:
                    return Command(update=update, goto=END)
                pick = _route(
                    roster, llm,
                    state["messages"] + [{"role": "user", "content": reply["content"]}],
                    set(update["unvisited"]),
                )
                if pick == "TERMINATE":
                    return Command(update=update, goto=END)
                event("route", topology="swarm", next=pick)
                return Command(update=update, goto=pick)

            return handoff

        for name in names:
            graph.add_node(name, swarm_node(name), destinations=(*names, END))
        graph.add_edge(START, names[0])

    return graph.compile(), budget


def initial_state(query: str, query_level: Level = Level.USER, names=()) -> dict:
    """The run's starting state: the user query as the first contribution,
    labeled with its channel level."""
    query_tv = TaintedValue(value=f"[user] {query}", level=query_level, source="user_query")
    return {
        "messages": [{"role": "user", "content": query}],
        "contributions": [query_tv],
        "turns": 0,
        "unvisited": list(names),
        "next": "",
        "denied": {},
    }


def run_team_graph(
    spec: SystemSpec, llm, resolver: ToolResolver, query: str,
    query_level: Level = Level.USER, max_rounds: int = 2, monitor=None,
) -> list:
    graph, budget = build_team_graph(spec, llm, resolver, max_rounds, monitor=monitor)
    state = initial_state(query, query_level, [a.id for a in spec.agents])
    final = graph.invoke(state, config={"recursion_limit": 2 * budget + 5})
    return final["messages"]
