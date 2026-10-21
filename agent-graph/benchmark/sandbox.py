"""
Client to the sandbox MCP server (benchmark/sandbox_server.py). The agents run
synchronously, so this wraps the async MCP session: a background thread runs an
asyncio loop that owns a persistent `ClientSession` over a stdio subprocess, and
the sync methods below submit coroutines to it and block.

The reference monitor and the security labels stay here on the client; the
sandbox only executes and records. `reset()` clears the sandbox before each run,
`state()` returns its final effects for the goal oracle, and the agents are
given only the benchmark tools (not the `sandbox_*` control tools).
"""

import asyncio
import json
import os
import sys
import threading
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

SERVER = Path(__file__).resolve().parent / "sandbox_server.py"
CONTROL_TOOLS = {"sandbox_reset", "sandbox_state"}


class Sandbox:
    def __init__(self, python_executable: str = sys.executable):
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True).start()
        params = StdioServerParameters(
            command=python_executable, args=[str(SERVER)],
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        self._submit(self._connect(params)).result(timeout=60)
        self._tool_names = [t for t in self._list() if t not in CONTROL_TOOLS]

    async def _connect(self, params):
        self._cm = stdio_client(params)
        read, write = await self._cm.__aenter__()
        self._session = ClientSession(read, write)
        await self._session.__aenter__()
        await self._session.initialize()

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    def _text(self, result) -> str:
        if result.content and hasattr(result.content[0], "text"):
            return result.content[0].text
        return ""

    def _list(self) -> list[str]:
        return [t.name for t in self._submit(self._session.list_tools()).result(timeout=60).tools]

    def tool_names(self) -> list[str]:
        return list(self._tool_names)

    def call(self, name: str, args: dict | None = None) -> str:
        return self._text(self._submit(self._session.call_tool(name, args or {})).result(timeout=60))

    def reset(self) -> None:
        self.call("sandbox_reset")

    def state(self) -> list[dict]:
        return json.loads(self.call("sandbox_state") or "[]")

    def close(self) -> None:
        async def _shutdown():
            await self._session.__aexit__(None, None, None)
            await self._cm.__aexit__(None, None, None)
        try:
            self._submit(_shutdown()).result(timeout=30)
        except Exception:  # noqa: BLE001
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
