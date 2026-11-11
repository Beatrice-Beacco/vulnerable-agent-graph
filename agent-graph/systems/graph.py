import operator
import os
import re
from typing import Annotated, Callable, TypedDict, cast

from langchain.messages import AIMessage
from langgraph.errors import GraphRecursionError
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from systems.agent import build_monitored_agent
from security import dataflow
from security.labels import Label
from security.security_context import build_security_context
from security.trace import event
from state import Level, TaintedValue
from engine.system import SystemSpec

RECURSION_LIMIT = int(os.getenv("TEAM_RECURSION_LIMIT", "40"))

SUPERVISOR = "supervisor"
TEAM_TOPOLOGIES = ("round_robin", "supervisor", "swarm")

ToolResolver = Callable[[str], object]

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_SUPPRESS_THINKING = (
    os.getenv("LLM_BACKEND", "openai").strip().lower() == "ollama"
    and os.getenv("ENABLE_THINKING", "0") != "1"
)


def _strip_think(text: str) -> str:
    return _THINK.sub("", text or "").strip()


def _prompt(prompt: str) -> str:
    return f"{prompt}\n\n/no_think" if _SUPPRESS_THINKING else prompt


class TeamState(TypedDict):
    messages: Annotated[list, operator.add]
    contributions: Annotated[list, operator.add]
    turns: int
    unvisited: list[str]
    next: str
    denied: dict


def _agent_tools(spec_agent, resolver: ToolResolver) -> list:
    return [resolver(name) for name in spec_agent.tools]


def _context(name: str, contributions: list, denied):
    fields = {f"turn_{i}": tv for i, tv in enumerate(contributions)}
    context = build_security_context(fields, origin=name)
    context.denied_tools = set(denied or ())
    return context


def _turn(name: str, agent, state: TeamState) -> dict:
    print(f"\n-- {name} --")
    context = _context(name, state["contributions"], state["denied"].get(name, ()))
    n_in = len(state["messages"])
    try:
        result = agent.invoke(
            {"messages": state["messages"]},
            context=context,
            config={"recursion_limit": RECURSION_LIMIT},
        )
        new = result["messages"][n_in:]
        texts = [_strip_think(m.text) for m in new if isinstance(m, AIMessage) and m.text]
        text = next((t for t in reversed(texts) if t), "")
    except PermissionError as exc:
        event("turn_stopped", agent=name, reason=str(exc))
        text = "(stopped by the security monitor)"
    except GraphRecursionError:
        event("turn_stopped", agent=name, reason="recursion limit")
        text = "(turn cut off: step limit)"
    labeled = context.labeled(f"[{name}] {text}", source=name)
    if dataflow.enabled():
        dataflow.record(labeled.value, dataflow.label_for(text))
    return {"role": "user", "content": labeled.value, "tainted": labeled,
            "denied": sorted(context.denied_tools)}


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
    except Exception:
        reply = ""
    if terminate_ok and "TERMINATE" in reply.upper():
        return "TERMINATE"
    for n in allowed:
        if n.lower() in reply.lower():
            return n
    return allowed[0]


def build_team_graph(spec: SystemSpec, llm, resolver: ToolResolver, max_rounds: int = 2, monitor=None):
    if spec.topology not in TEAM_TOPOLOGIES:
        raise ValueError(f"{spec.topology!r} is not a team topology {TEAM_TOPOLOGIES}")
    names = [a.id for a in spec.agents]
    if len(set(names)) != len(names) or SUPERVISOR in names:
        raise ValueError(f"agent ids must be unique and not {SUPERVISOR!r}: {names}")
    agents = {
        a.id: build_monitored_agent(llm, a.id, _prompt(a.prompt), _agent_tools(a, resolver), monitor=monitor)
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

    else:
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
    if dataflow.enabled():
        dataflow.reset()
        dataflow.record(query, Label(query_level))
    state = initial_state(query, query_level, [a.id for a in spec.agents])
    final = graph.invoke(state, config={"recursion_limit": 2 * budget + 5})
    return final["messages"]
