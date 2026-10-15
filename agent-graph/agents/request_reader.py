from dataclasses import dataclass

from langchain.messages import ToolMessage

from agents.base import build_agent
from security.security_context import build_security_context
from state import TaintedValue, Level
from tools.internal import read_internal_instruction

AGENT_ID = "RequestReaderAgent"

SYSTEM_PROMPT = """
You are an AI agent that is able to read the internal instructions from the file system.

You can use the following tools to read the internal instructions:
- read_internal_instruction: reads the internal instruction from the file system and returns the content of the internal instruction.
"""


@dataclass
class RequestReaderOutput:
    content: str


def create_request_reader_agent(llm):
    return build_agent(
        llm,
        AGENT_ID,
        SYSTEM_PROMPT,
        tools=[read_internal_instruction],
        response_format=RequestReaderOutput,
    )


def run_request_reader_node(state, request_reader_agent):
    print("-- READ INTERNAL INSTRUCTION AGENT --")

    response = request_reader_agent.invoke(
        {"messages": [{"role": "user", "content": state["user_prompt"].value}]},
        context=build_security_context(
            {"user_prompt": state["user_prompt"]}, origin=AGENT_ID
        ),
    )
    structured_response = response.get("structured_response", response)

    content = structured_response.content.strip().strip('"').strip("'")

    # The TRUSTED label below belongs to what the tool read: the parser gets
    # the request exactly as read, not re-emitted by this agent's LLM.
    raw = [
        str(message.content)
        for message in response["messages"]
        if isinstance(message, ToolMessage)
        and message.name == read_internal_instruction.name
    ]
    if raw:
        content = raw[-1].strip()

    return {
        "internal_request": TaintedValue(
            value=content,
            level=Level.INTERNAL,
            source="read_internal_instruction",
            provenance=["read_internal_instruction"],
        )
    }
