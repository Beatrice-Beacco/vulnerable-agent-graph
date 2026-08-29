from dataclasses import dataclass

from langchain.agents import create_agent
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
        response_format=ReadEmailAgentOutput,
        tools=[read_email],
    )
    return agent


def run_read_email_node(state, read_email_agent):
    print("-- READ EMAIL AGENT --")

    response = read_email_agent.invoke(
        {"messages": [{"role": "user", "content": state["user_prompt"].value}]}
    )
    structured_response = response.get("structured_response", response)

    # structured_response may be a dataclass-like object or a plain dict.
    if isinstance(structured_response, dict):
        content = structured_response.get("content", "")
    else:
        content = getattr(structured_response, "content", "")

    content = content.strip().strip('"').strip("'")

    return {
        "email": TaintedValue(
            value=content,
            integrity=Integrity.UNTRUSTED,
            source="read_email",
            provenance=["read_email"],
        )
    }
