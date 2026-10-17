"""
Loads the vendored TAMAS tool functions and wraps them as sync LangChain
tools, so they run through this project's agents (and the monitor middleware).
The tool functions are `async def` but do no awaiting (they return a string),
so a sync wrapper runs the coroutine to completion.
"""

import asyncio
import importlib.util
import inspect
from pathlib import Path

from langchain_core.tools import StructuredTool

VENDOR_TOOLS = Path(__file__).resolve().parent / "vendor" / "tools"

# Agent name (as it appears in an instance's `agents`) -> tool module stem.
# Suffixes like " A"/" B" (colluding) are stripped before lookup.
_MODULE_CACHE: dict[str, object] = {}


def _module(stem: str):
    if stem not in _MODULE_CACHE:
        path = VENDOR_TOOLS / f"{stem}.py"
        spec = importlib.util.spec_from_file_location(stem, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _MODULE_CACHE[stem] = mod
    return _MODULE_CACHE[stem]


# Agent display names whose module stem is not the plain normalization of the
# name (TAMAS names some agents differently from their tool file).
_ALIAS = {
    "case_analysis": "tools_analysis_agent",
    "compliance_check": "tools_compliance_agent",
    "document_drafting": "tools_doc_draft_agent",
    "legal_research": "tools_research_agent",
    "medication_adherence": "tools_medical_adherence_agent",
    "real_time_monitoring": "tools_realtime_monitoring_agent",
}


def module_for_agent(agent_name: str) -> str:
    """'Trade Execution Agent B' -> 'tools_trade_execution_agent'."""
    name = agent_name.strip()
    for suffix in (" A", " B", " C"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    key = name.lower().removesuffix(" agent").strip().replace(" ", "_")
    return _ALIAS.get(key, f"tools_{key}_agent")


def _sync_tool(afn) -> StructuredTool:
    """Wrap a TAMAS async tool function as a sync LangChain StructuredTool."""

    def wrapper(*args, **kwargs):
        return asyncio.run(afn(*args, **kwargs))

    wrapper.__name__ = afn.__name__
    wrapper.__doc__ = afn.__doc__ or afn.__name__
    wrapper.__signature__ = inspect.signature(afn)
    wrapper.__annotations__ = dict(getattr(afn, "__annotations__", {}))
    return StructuredTool.from_function(
        wrapper, name=afn.__name__, description=afn.__doc__ or afn.__name__
    )


def tools_for_agent(agent_name: str) -> list[StructuredTool]:
    """All tools of the agent's module, as sync LangChain tools."""
    mod = _module(module_for_agent(agent_name))
    fns = [
        fn
        for _, fn in inspect.getmembers(mod, inspect.iscoroutinefunction)
        if fn.__module__ == mod.__name__
    ]
    return [_sync_tool(fn) for fn in fns]


def tool_names_for_agent(agent_name: str) -> list[str]:
    mod = _module(module_for_agent(agent_name))
    return [
        name
        for name, fn in inspect.getmembers(mod, inspect.iscoroutinefunction)
        if fn.__module__ == mod.__name__
    ]
