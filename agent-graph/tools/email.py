import os
from pathlib import Path

from langchain.tools import tool

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Messages sent by the agents (simulated mail server). Every message is an
# egress of data outside the graph.
OUTBOX: list[dict] = []


@tool
def read_email(file_path: str) -> str:
    """Reads an email from the file system.

    Args:
        file_path (str): The path to the email file.

    Returns:
        str: The content of the email.
    """
    # The scenario is chosen with EMAIL_FILE, not by the agent.
    data_path = DATA_DIR / os.getenv("EMAIL_FILE", "malicious_email.txt")

    with data_path.open(encoding="utf-8") as f:
        email = f.read()

    return email


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Sends an email.

    Args:
        to (str): The recipient address.
        subject (str): The subject.
        body (str): The body of the email.
    """
    OUTBOX.append({"to": to, "subject": subject, "body": body})
    print(f"[MAIL] Sent to {to}: {subject}")
    return f"email sent to {to}"
