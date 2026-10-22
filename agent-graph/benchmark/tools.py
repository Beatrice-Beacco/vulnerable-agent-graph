import inspect

from langchain_core.tools import StructuredTool

from benchmark import catalog

_TYPES = {"str": str, "int": int, "float": float, "bool": bool, "list": list, "dict": dict}

_ALIAS = {
    "case_analysis": "tools_analysis_agent",
    "compliance_check": "tools_compliance_agent",
    "document_drafting": "tools_doc_draft_agent",
    "legal_research": "tools_research_agent",
    "medication_adherence": "tools_medical_adherence_agent",
    "real_time_monitoring": "tools_realtime_monitoring_agent",
}


def module_for_agent(agent_name: str) -> str:
    name = agent_name.strip()
    for suffix in (" A", " B", " C"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    key = name.lower().removesuffix(" agent").strip().replace(" ", "_")
    return _ALIAS.get(key, f"tools_{key}_agent")


def _build_tool(name: str, sandbox) -> StructuredTool:
    e = catalog.entry(name)

    def wrapper(*args, **kwargs):
        return sandbox.call(name, kwargs)

    params = [
        inspect.Parameter(
            p["name"], inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=_TYPES.get(p["type"], str),
        )
        for p in e["params"]
    ]
    wrapper.__name__ = name
    wrapper.__doc__ = e.get("doc") or name
    wrapper.__signature__ = inspect.Signature(params)
    wrapper.__annotations__ = {p["name"]: _TYPES.get(p["type"], str) for p in e["params"]}
    return StructuredTool.from_function(wrapper, name=name, description=e.get("doc") or name)


def tool_names_for_agent(agent_name: str) -> list[str]:
    return catalog.names_in_module(module_for_agent(agent_name))


def tools_for_agent(agent_name: str, sandbox) -> list[StructuredTool]:
    return [_build_tool(name, sandbox) for name in tool_names_for_agent(agent_name)]
