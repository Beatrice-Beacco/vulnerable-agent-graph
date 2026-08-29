from dataclasses import dataclass

from langchain.agents import create_agent
from state import TaintedValue, Integrity
from tools.internal import read_internal_instruction

SYSTEM_PROMPT = """
You are an AI agent that is able to read the internal instructions from the file system.

You can use the following tools to read the internal instructions:
- read_internal_instruction: reads the internal instruction from the file system and returns the content of the internal instruction.
"""


@dataclass
class RequestReaderOutput:
    content: str


def create_request_reader_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        response_format=RequestReaderOutput,
        tools=[read_internal_instruction],
    )
    return agent


def run_request_reader_node(state, request_reader_agent):
    print("-- READ INTERNAL INSTRUCTION AGENT --")

    response = request_reader_agent.invoke(
        {"messages": [{"role": "user", "content": state["user_prompt"].value}]}
    )
    structured_response = response.get("structured_response", response)

    content = structured_response.content.strip().strip('"').strip("'")

    return {
        "internal_request": TaintedValue(
            value=content,
            integrity=Integrity.TRUSTED,
            source="read_internal_instruction",
            provenance=["read_internal_instruction"],
        )
    }
