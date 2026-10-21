"""
The sandbox: an MCP server that executes the benchmark tools in a separate
process, isolated from the reference monitor. It serves every tool from the
catalog (name, parameters, the string it returns) and records each executed
call as an *effect* in resettable in-memory state. It holds NO security labels
and enforces NO policy -- those stay on the client (the monitor). The effects
are the sandbox's final state, which the goal oracle checks.

Control tools (not given to the agents): `sandbox_reset` clears the state
before a run, `sandbox_state` returns the recorded effects as JSON.

    python -m benchmark.sandbox_server      # runs over stdio
"""

import inspect
import json
from pathlib import Path

from mcp.server import MCPServer

CATALOG = json.loads((Path(__file__).resolve().parent / "catalog.json").read_text(encoding="utf-8"))

_TYPES = {"str": str, "int": int, "float": float, "bool": bool, "list": list, "dict": dict}
_DEFAULT = {"str": "", "int": 0, "float": 0.0, "bool": False, "list": [], "dict": {}}

# The sandbox state: the ordered effects of the executed tool calls.
STATE: list[dict] = []


def _make_tool(name: str, entry: dict):
    returns = entry["returns"]

    def fn(**kwargs):
        STATE.append({"tool": name, "args": kwargs})
        return returns

    # Signature from the catalog, every parameter optional (the sandbox only
    # records the call; it does not require well-formed arguments).
    params = [
        inspect.Parameter(
            p["name"], inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=_DEFAULT.get(p["type"], ""), annotation=_TYPES.get(p["type"], str),
        )
        for p in entry["params"]
    ]
    fn.__name__ = name
    fn.__doc__ = entry.get("doc") or name
    fn.__signature__ = inspect.Signature(params)
    fn.__annotations__ = {p["name"]: _TYPES.get(p["type"], str) for p in entry["params"]}
    return fn


def build_server() -> MCPServer:
    server = MCPServer(name="benchmark-sandbox")
    for name, entry in CATALOG.items():
        server.add_tool(_make_tool(name, entry), name=name, description=entry.get("doc") or name)

    def sandbox_reset() -> str:
        STATE.clear()
        return "reset"

    def sandbox_state() -> str:
        return json.dumps(STATE)

    server.add_tool(sandbox_reset, name="sandbox_reset", description="Clear the sandbox state.")
    server.add_tool(sandbox_state, name="sandbox_state", description="Return the sandbox effects as JSON.")
    return server


if __name__ == "__main__":
    build_server().run("stdio")
