from dataclasses import dataclass

from langchain.messages import ToolMessage

from agents.base import build_agent
from security.security_context import build_security_context
from state import TaintedValue, Level
from tools.email import read_email

AGENT_ID = "EmailReaderAgent"

SYSTEM_PROMPT = """
You are an AI agent that is able to read the emails from the file system.

You can use the following tools to read the emails:
- read_email: reads the email from the file system and returns the content of the email.
"""


@dataclass
class ReadEmailAgentOutput:
    content: str


def create_read_email_agent(llm):
    return build_agent(llm, AGENT_ID, SYSTEM_PROMPT, tools=[read_email])


def run_read_email_node(state, read_email_agent):
    print("-- READ EMAIL AGENT --")

    response = read_email_agent.invoke(
        {"messages": [{"role": "user", "content": state["user_prompt"].value}]},
        context=build_security_context(
            {"user_prompt": state["user_prompt"]}, origin=AGENT_ID
        ),
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
            level=Level.UNTRUSTED_EXTERNAL,
            source="read_email",
            provenance=["read_email"],
        )
    }
