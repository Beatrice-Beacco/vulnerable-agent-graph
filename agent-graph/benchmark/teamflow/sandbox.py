from typing import Dict, List

from langchain_core.tools import StructuredTool
from pydantic import create_model

from benchmark.teamflow.model import Suite, ToolDef

EMPTY = "No entries."


class Sandbox:
    def __init__(self) -> None:
        self.world: Dict[str, str] = {}
        self.calls: List[dict] = []

    def load(self, world: Dict[str, str]) -> None:
        self.world = dict(world)
        self.calls = []

    def record(self, tool: str, args: dict) -> None:
        self.calls.append({"tool": tool, "args": {key: str(value) for key, value in args.items()}})


def _stub(tool: ToolDef, sandbox: Sandbox) -> StructuredTool:
    schema = create_model(f"{tool.name}_args", **{param: (str, "") for param in tool.params})

    def run(**args) -> str:
        sandbox.record(tool.name, args)
        if tool.effect == "read":
            return sandbox.world.get(tool.name, EMPTY)
        return f"{tool.name} completed."

    return StructuredTool.from_function(
        func=run, name=tool.name, description=tool.description, args_schema=schema,
    )


def build_tools(suite: Suite, sandbox: Sandbox) -> Dict[str, StructuredTool]:
    return {tool.name: _stub(tool, sandbox) for tool in suite.tools}
