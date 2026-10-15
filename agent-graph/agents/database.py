from langchain.messages import ToolMessage

from tools.crm import read_customer, write_customer, delete_customer
from agents.base import build_agent
from security.security_context import OperationBinding, build_security_context

SYSTEM_PROMPT = """
You are a CRM execution agent.

You MUST use the available tools to execute the requested operation.

Rules:

- Never simulate tool execution.
- Never answer directly.
- You cannot send emails: sending is done by another agent.

Available operations:

delete_customer: use the delete_customer tool.
update_customer: use the write_customer tool with the given field and value.
send_customer_data: read ONLY the requested fields with the read_customer
    tool. Do not send them.
"""


def create_database_agent(llm):
    return build_agent(
        llm,
        "DatabaseAgent",
        SYSTEM_PROMPT,
        tools=[read_customer, write_customer, delete_customer],
    )


def run_database_node(state, database_agent):

    print("-- DATABASE AGENT --")

    fields = {
        "operation": state["operation_type"],
        "customer": state["target_customer_id"],
        "field": state["update_field"],
        "value": state["update_value"],
    }

    # Label of everything the agent receives: the monitor updates it with
    # the output of every tool call.
    context = build_security_context(
        fields, origin="DatabaseAgent", binding=OperationBinding.of(state)
    )

    print(
        "Database fields:",
        {name: value.value for name, value in fields.items()},
        f"[{context.level.name}, {context.confidentiality.name}]",
    )

    try:
        result = database_agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": f"""
                        Operation: {fields["operation"].value}
                        Customer: {fields["customer"].value}
                        Field: {fields["field"].value}
                        Value: {fields["value"].value}
                        """,
                    }
                ],
            },
            context=context,
        )
    except PermissionError as exc:
        print("DATABASE AUTHORIZATION BLOCKED:", exc)
        return {"database_status": "blocked"}

    print("Database agent result:", result["messages"][-1].content)
    print(
        f"Final context label: {context.level.name}, "
        f"{context.confidentiality.name}, {sorted(context.provenance)}"
    )

    update = {"database_status": "executed"}

    # Customer data read by the agent is handed to the email agent through the
    # state, with the label of the agent's context (the read fields included).
    customer_data = [
        str(message.content)
        for message in result["messages"]
        if isinstance(message, ToolMessage) and message.name == read_customer.name
    ]
    if customer_data:
        update["customer_data"] = context.labeled(
            "\n".join(customer_data), source="database_agent"
        )

    return update
