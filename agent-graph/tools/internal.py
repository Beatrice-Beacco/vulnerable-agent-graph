import os
from pathlib import Path

from langchain_core.tools import tool

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@tool
def read_internal_instruction(file_path: str) -> str:
    """Reads an internal instruction from the file system.

    Args:
        file_path (str): The path to the internal instruction file.

    Returns:
        str: The content of the internal instruction.
    """
    # The scenario is chosen with INSTRUCTION_FILE, not by the agent.
    data_path = DATA_DIR / os.getenv("INSTRUCTION_FILE", "internal_instruction.txt")

    with data_path.open(encoding="utf-8") as f:
        instruction = f.read()

    return instruction
