from benchmark.manifest import _required_level
from benchmark.teamflow.model import SLOTS, ToolDef
from benchmark.teamflow.suites import CASES, SUITES
from engine.tool_contract import CedarRequest, ToolDeclaration, register
from security.labels import Label
from state import Confidentiality, Level

SYSTEM = "teamflow"


def _declaration(tool: ToolDef) -> ToolDeclaration:
    slot = SLOTS[tool.slot]
    effect = slot.effect
    data_conf = Confidentiality[slot.data_conf]
    sink = Confidentiality[slot.sink_clearance]
    required = _required_level(effect, data_conf, sink)
    out = Level[slot.output_level]
    name = tool.name

    def context(args, ctx, _effect=effect, _dc=data_conf, _sink=sink):
        return {
            "effect": _effect,
            "data_conf": int(_dc),
            "sink_clearance": int(_sink),
            "denied_tools": sorted(getattr(ctx, "denied_tools", set())),
        }

    def output_label(args, _effect=effect, _out=out, _dc=data_conf, _name=name):
        if _effect == "read":
            return Label(_out, _dc, frozenset({f"tool:{_name}"}))
        return Label.bottom()

    return ToolDeclaration(
        name=name,
        requests=lambda args, _n=name: [CedarRequest(_n, "Call", "call")],
        required_level=required,
        context=context,
        output_label=output_label,
        resource_type="Call",
        system=SYSTEM,
    )


def register_teamflow_tools() -> None:
    for suite in SUITES.values():
        for tool in suite.tools:
            register(_declaration(tool))


register_teamflow_tools()

__all__ = ["CASES", "SUITES", "SYSTEM"]
