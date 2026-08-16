from langchain.agents import create_agent

from tools.crm import write_customer
from tools.crm import delete_customer
from security.authorization_middleware import CedarAuthorizationMiddleware
from security.security_context import build_security_context

SYSTEM_PROMPT = """
You are a CRM execution agent.

You MUST use the available tools to execute the requested operation.

Rules:

- Never simulate tool execution.
- Never answer directly.
- Always call exactly one tool.

Available operations:

delete_customer use the delete_customer tool.
update_customer use the write_customer tool.

"""


def create_database_agent(llm):
    agent = create_agent(
        model=llm,
        system_prompt=SYSTEM_PROMPT,
        tools=[write_customer, delete_customer],
        middleware=[CedarAuthorizationMiddleware(agent_id="DatabaseAgent")],
    )
    return agent


def run_database_node(state, database_agent):

    print("-- DATABASE AGENT --")

    operation = state["crm_operation"]
    customer = state["customer_id"]

    context = build_security_context(
        {
            "operation": operation,
            "customer": customer,
        },
        origin="database_node",
    )

    try:
        result = database_agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": f"""
                        Operation: {operation.value}
                        Customer: {customer.value}
                        """,
                    }
                ],
            },
            context=context,
        )
    except PermissionError as exc:
        print("DATABASE AUTHORIZATION BLOCKED:", exc)
        return {"database_status": "blocked"}

    print("Database agent result:", result)

    return {"database_status": "executed"}
