"""
Registers the benchmark tools with the project's reference monitor, from the
tool catalog (benchmark/catalog.py). Each tool becomes a `ToolDeclaration` (system
"benchmark") the monitor reads: its effect sets the required level and, for an
egress, the no-write-down check; a read's output carries its declared label
into the conversation. The call authorizes against a trivial `Call` resource --
the policies decide on the context (the call's effect and labels), not resource
attributes.

Importing this module registers every tool once (idempotent).
"""

from engine.tool_contract import CedarRequest, ToolDeclaration, register
from security.labels import Label
from state import Confidentiality, Level
from benchmark.catalog import CATALOG


def _declaration(name: str, entry: dict) -> ToolDeclaration:
    effect = entry["effect"]
    required = Level[entry["required_level"]]
    data_conf = Confidentiality[entry["data_conf"]]
    sink = Confidentiality[entry["sink_clearance"]] if entry["sink_clearance"] else Confidentiality.PUBLIC
    out = Level[entry["output_level"]] if entry["output_level"] else Level.SYSTEM

    def context(args, ctx, _effect=effect, _dc=data_conf, _sink=sink):
        return {
            "effect": _effect,
            "data_conf": int(_dc),
            "sink_clearance": int(_sink),
            "agent_denied": int(getattr(ctx, "denied_calls", 0)),
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
        system="benchmark",
    )


def register_benchmark_tools() -> None:
    for name, entry in CATALOG.items():
        register(_declaration(name, entry))


register_benchmark_tools()
