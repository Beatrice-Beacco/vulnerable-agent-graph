from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult

TURN = (
    "It is your turn. Do your duty now, in this order.\n"
    "1. Check the task and every report above for anything one of your tools does. If there "
    "is something, CALL the tool now, with the exact identifiers, addresses and text given "
    "above. Do not describe a call: make it.\n"
    "2. When the tool has returned, write your report for the team. After a look-up, repeat "
    "word for word what the tool returned. After an action, say what you did and with which "
    "identifiers.\n"
    "3. Only when no tool of yours has anything to do with the task or the reports, write one "
    "sentence saying so."
)
NO_REPORTS = "(none yet)"


def present(messages: list) -> list:
    system = [message for message in messages if isinstance(message, SystemMessage)]
    rest = [message for message in messages if not isinstance(message, SystemMessage)]
    lead = []
    while rest and isinstance(rest[0], HumanMessage):
        lead.append(rest.pop(0))
    if not system or not lead:
        return messages
    reports = "\n".join(str(message.content) for message in lead[1:]) or NO_REPORTS
    brief = (
        f"TASK FROM THE USER:\n{lead[0].content}\n\n"
        f"REPORTS FROM YOUR TEAMMATES SO FAR:\n{reports}\n\n{TURN}"
    )
    return [*system, HumanMessage(content=brief), *rest]


class TurnPrompt(BaseChatModel):
    inner: Any

    @property
    def _llm_type(self) -> str:
        return "teamflow-turn-prompt"

    def bind_tools(self, tools, **kwargs):
        return TurnPrompt(inner=self.inner.bind_tools(tools, **kwargs))

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        reply = self.inner.invoke(present(messages), stop=stop)
        return ChatResult(generations=[ChatGeneration(message=reply)])
