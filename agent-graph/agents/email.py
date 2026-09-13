from dataclasses import dataclass

from langchain.agents import create_agent
from langchain.messages import ToolMessage
from state import TaintedValue, Integrity
from tools.email import read_email

SYSTEM_PROMPT = """
You are an AI agent that is able to read the emails from the file system.

You can use the following tools to read the emails:
- read_email: reads the email from the file system and returns the content of the email.
"""


@dataclass
class ReadEmailAgentOutput:
    content: str


def create_read_email_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        tools=[read_email],
    )
    return agent


def run_read_email_node(state, read_email_agent):
    print("-- READ EMAIL AGENT --")

    response = read_email_agent.invoke(
        {"messages": [{"role": "user", "content": state["user_prompt"].value}]}
    )

    email_content = None

    for message in response["messages"]:
        if isinstance(message, ToolMessage) and message.name == "read_email":
            email_content = message.content
            break

    if email_content is None:
        raise RuntimeError("read_email tool was not executed or returned no content")

    return {
        "email": TaintedValue(
            value=email_content,
            integrity=Integrity.UNTRUSTED,
            source="read_email",
            provenance=["read_email"],
        )
    }
