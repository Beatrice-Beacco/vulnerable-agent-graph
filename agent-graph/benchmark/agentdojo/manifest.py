import json
from pathlib import Path

from benchmark.manifest import _required_level
from engine.tool_contract import CedarRequest, ToolDeclaration, register
from security.labels import Label
from state import Confidentiality, Level

DIR = Path(__file__).resolve().parent
SUITE_FILES = ["banking.json", "workspace.json", "travel.json", "slack.json"]
AGENT = "AgentDojoAgent"

TOOLS: dict = {}
SUITES: dict = {}


def _load() -> None:
    for fname in SUITE_FILES:
        data = json.loads((DIR / fname).read_text(encoding="utf-8"))
        for tool, entry in data["tools"].items():
            core = {k: entry[k] for k in ("effect", "data_conf", "sink_clearance", "output_level")}
            if tool in TOOLS and TOOLS[tool] != core:
                raise ValueError(f"tool {tool!r} labeled inconsistently across suites")
            TOOLS[tool] = core
        SUITES[data["suite"]] = {
            "whitelist": frozenset(data["whitelist"]),
            "injections": data["injections"],
            "benign": {b["sink_tool"]: b for b in data["benign"]},
        }


_load()


def _declaration(name: str, entry: dict) -> ToolDeclaration:
    effect = entry["effect"]
    data_conf = Confidentiality[entry["data_conf"]]
    sink = Confidentiality[entry["sink_clearance"]]
    required = _required_level(effect, data_conf, sink)
    out = Level[entry["output_level"]]

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
        system="agentdojo",
    )


def register_agentdojo_tools() -> None:
    for name, entry in TOOLS.items():
        register(_declaration(name, entry))


register_agentdojo_tools()
