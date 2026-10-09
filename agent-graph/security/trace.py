"""
Run log: one JSON object per line, one file per run (runs/ at the repository
root, or RUN_DIR). The log is the only input of the verifier (verify.py): the
scenario, the CRM before and after, every tool call mediated by the monitor
and every agent output are written here, and the verdict is computed from
this file alone, by code.

Events: run_start, agent_output, tool_call, node_output, run_end.
"""

import dataclasses
import json
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import AIMessage

from state import TaintedValue

RUN_DIR = Path(os.getenv("RUN_DIR", Path(__file__).resolve().parents[2] / "runs"))


def jsonable(value: Any) -> Any:
    if isinstance(value, TaintedValue):
        return {
            "value": jsonable(value.value),
            "integrity": value.integrity.name,
            "confidentiality": value.confidentiality.name,
            "provenance": list(value.provenance),
        }
    if isinstance(value, Enum):
        return value.name
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class RunLog:
    def __init__(self):
        self.path: Optional[Path] = None
        self._seq = 0

    def open(self, name: str) -> Path:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        self.path = RUN_DIR / f"{stamp}_{name}.jsonl"
        self._seq = 0
        return self.path

    def event(self, kind: str, **data: Any) -> None:
        if self.path is None:
            return
        self._seq += 1
        record = {"seq": self._seq, "ts": datetime.now().isoformat(), "event": kind}
        record.update(jsonable(data))
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


LOG = RunLog()


def event(kind: str, **data: Any) -> None:
    LOG.event(kind, **data)


def context_label(context) -> dict:
    return {
        "integrity": context.integrity.name,
        "confidentiality": context.confidentiality.name,
        "provenance": sorted(context.provenance),
    }


class AgentOutputLog(AgentMiddleware):
    """Logs what an agent produced: its structured output and last message."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def after_agent(self, state, runtime):
        final = next(
            (m.content for m in reversed(state["messages"]) if isinstance(m, AIMessage)),
            None,
        )
        event(
            "agent_output",
            agent=self.agent_id,
            structured=state.get("structured_response"),
            final_message=final,
        )
        return None
