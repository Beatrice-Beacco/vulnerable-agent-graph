from typing import Any, Dict, List, Tuple

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from benchmark.teamflow.model import ROLES, Step

IDLE = "No part for me here."
DONE = "Done."
STOP = "TERMINATE"


def schedule(steps) -> Dict[Tuple[int, int], List[Step]]:
    order = {role: index for index, role in enumerate(ROLES)}
    plan: Dict[Tuple[int, int], List[Step]] = {}
    turn_round, cursor = 0, -1
    for step in steps:
        index = order[step.role]
        if index < cursor:
            turn_round += 1
        cursor = index
        plan.setdefault((turn_round, index), []).append(step)
    return plan


def identity(agent_id: str) -> str:
    return f"You are {agent_id},"


class ScriptedModel(BaseChatModel):
    roster: Tuple[str, ...]
    plan: Dict[Any, Any]
    progress: Dict[str, Any]

    @classmethod
    def replay(cls, roster, steps) -> "ScriptedModel":
        return cls(
            roster=tuple(roster),
            plan=schedule(steps),
            progress={"started": 0, "calls": 0, "turns": [0] * len(roster), "position": {}},
        )

    @property
    def _llm_type(self) -> str:
        return "teamflow-scripted"

    def bind_tools(self, tools, **kwargs):
        return self

    def _last(self) -> Tuple[int, int]:
        return max(self.plan) if self.plan else (-1, -1)

    def _route(self) -> AIMessage:
        started = self.progress["started"]
        index, turn_round = started % len(self.roster), started // len(self.roster)
        if (turn_round, index) > self._last():
            return AIMessage(content=STOP)
        return AIMessage(content=self.roster[index])

    def _act(self, system: str, last) -> AIMessage:
        index = next(i for i, name in enumerate(self.roster) if identity(name) in system)
        if isinstance(last, ToolMessage):
            turn_round, position = self.progress["position"][index]
        else:
            turn_round, position = self.progress["turns"][index], 0
            self.progress["turns"][index] += 1
            self.progress["started"] += 1
        steps = self.plan.get((turn_round, index), [])
        if position < len(steps):
            self.progress["position"][index] = (turn_round, position + 1)
            step = steps[position]
            if step.is_call:
                self.progress["calls"] += 1
                return AIMessage(content="", tool_calls=[{
                    "name": step.tool, "args": dict(step.args),
                    "id": f"call_{self.progress['calls']}", "type": "tool_call",
                }])
            return AIMessage(content=step.say)
        self.progress["position"][index] = (turn_round, position)
        if steps:
            return AIMessage(content=DONE)
        return AIMessage(content=STOP if (turn_round, index) > self._last() else IDLE)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        system = next((str(m.content) for m in messages if isinstance(m, SystemMessage)), None)
        message = self._route() if system is None else self._act(system, messages[-1])
        return ChatResult(generations=[ChatGeneration(message=message)])
