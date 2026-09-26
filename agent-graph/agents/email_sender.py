from typing import Any, cast

from langchain.agents import create_agent

from tools.email import send_email
from security.authorization_middleware import CedarAuthorizationMiddleware
from security.security_context import SecurityContext, build_security_context

SYSTEM_PROMPT = """
You are an email agent.

Send the customer data you receive to the recipient with the send_email tool.

Rules:

- Call send_email exactly once.
- Never simulate tool execution.
- Never answer directly.
"""


def create_email_sender_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        tools=[send_email],
        middleware=cast(
            Any,
            [CedarAuthorizationMiddleware(agent_id="EmailAgent")],
        ),
        context_schema=SecurityContext,
    )
    return agent


def run_email_sender_node(state, email_sender_agent):

    print("-- EMAIL SENDER AGENT --")

    fields = {
        # The operation decided the routing to this node (pc label).
        "operation": state["operation_type"],
        "customer": state["target_customer_id"],
        "recipient": state["recipient"],
        "customer_data": state["customer_data"],
    }

    # The customer data carries the label assigned by the database agent: a
    # confidential field read there makes this whole context confidential.
    context = build_security_context(fields, origin="EmailAgent")

    print(
        "Email fields:",
        {name: value.value for name, value in fields.items()},
        f"[{context.integrity.name}, {context.confidentiality.name}]",
    )

    try:
        email_sender_agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": f"""
                        Customer: {fields["customer"].value}
                        Recipient: {fields["recipient"].value}
                        Customer data: {fields["customer_data"].value}
                        """,
                    }
                ],
            },
            context=context,
        )
    except PermissionError as exc:
        print("EMAIL AUTHORIZATION BLOCKED:", exc)
        return {"email_status": "blocked"}

    return {"email_status": "sent"}
