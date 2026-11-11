from engine.tool_contract import CedarRequest, ToolDeclaration, register
from security.labels import Label
from state import Confidentiality, Level
from benchmark.catalog import CATALOG


def _required_level(effect: str, data_conf: Confidentiality, sink: Confidentiality) -> Level:
    if effect == "read":
        return Level.UNTRUSTED_EXTERNAL
    if effect == "critical":
        return Level.USER
    if effect == "write":
        return Level.EXTERNAL_KNOWN if data_conf == Confidentiality.PUBLIC else Level.INTERNAL
    if effect == "egress":
        if sink == Confidentiality.PUBLIC and data_conf == Confidentiality.PUBLIC:
            return Level.EXTERNAL_KNOWN
        return Level.INTERNAL
    return Level.INTERNAL


def _declaration(name: str, entry: dict) -> ToolDeclaration:
    effect = entry["effect"]
    data_conf = Confidentiality[entry["data_conf"]]
    sink = Confidentiality[entry["sink_clearance"]] if entry["sink_clearance"] else Confidentiality.PUBLIC
    required = _required_level(effect, data_conf, sink)
    out = Level[entry["output_level"]] if entry["output_level"] else Level.SYSTEM

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
        system="benchmark",
    )


def register_benchmark_tools() -> None:
    for name, entry in CATALOG.items():
        register(_declaration(name, entry))


register_benchmark_tools()
