from pathlib import Path

from langchain_core.tools import tool


@tool
def read_internal_instruction(file_path: str) -> str:
    """Reads an internal instruction from the file system.

    Args:
        file_path (str): The path to the internal instruction file.

    Returns:
        str: The content of the internal instruction.
    """
    data_path = (
        Path(__file__).resolve().parent.parent / "data" / "internal_instruction.txt"
    )

    with data_path.open() as f:
        email = f.read()

    return email
