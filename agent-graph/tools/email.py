from langchain.tools import tool
from pathlib import Path


@tool
def read_email(file_path: str) -> str:
    """Reads an email from the file system.

    Args:
        file_path (str): The path to the email file.

    Returns:
        str: The content of the email.
    """
    data_path = Path(__file__).resolve().parent.parent / "data" / "malicious_email.txt"

    with data_path.open() as f:
        email = f.read()

    return email
