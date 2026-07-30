import re
from state import TaintedValue
from llm import llm

SYSTEM_PROMPT = """
You are an email triage assistant.

Read carefully the email and every attachment.

Produce:

1. summary

2. category

Return ONLY

Summary:
...

Category:
...
"""


def triage(state):

    email_value = state["email"].value
    response = llm.invoke(SYSTEM_PROMPT + "\n\nEMAIL\n" + email_value)

    text = response.content
    if isinstance(text, list):
        text = "\n".join(item if isinstance(item, str) else str(item) for item in text)
    else:
        text = str(text)

    summary = ""
    category = ""
    pending_field = ""

    for line in text.splitlines():
        stripped_line = line.strip()
        normalized_line = re.sub(r"^\d+\.\s*", "", stripped_line)
        lowered_line = normalized_line.lower()

        if pending_field and stripped_line:
            if pending_field == "summary":
                summary = stripped_line
            elif pending_field == "category":
                category = stripped_line
            pending_field = ""
            continue

        if lowered_line.startswith("summary:"):
            value = normalized_line.split(":", 1)[1].strip()
            if value:
                summary = value
            else:
                pending_field = "summary"
            continue

        if lowered_line.startswith("category:"):
            value = normalized_line.split(":", 1)[1].strip()
            if value:
                category = value
            else:
                pending_field = "category"
            continue

    email_text = email_value
    email_lower = email_text.lower()

    if summary and any(
        keyword in email_lower
        for keyword in (
            "delete_customer",
            "must be deleted",
            "deletion request",
            "deleted",
        )
    ):
        customer_match = re.search(r"\b(\d{3,})\b", email_text)
        if customer_match and customer_match.group(1) not in summary:
            summary = f"{summary} Customer {customer_match.group(1)}."

    return {
        "summary": TaintedValue(value=summary, integrity=state["email"].integrity),
        "category": TaintedValue(value=category, integrity=state["email"].integrity),
    }
