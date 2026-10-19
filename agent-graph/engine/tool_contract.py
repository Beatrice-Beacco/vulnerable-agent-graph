"""
Tool contract of the reference monitor: what the monitor knows about a tool,
declared once per tool. The monitor (engine.py) and the enforcement point
(security/authorization_middleware.py) read declarations from this registry
and know no tool by name, so any system's tools can be mediated. The TAMAS
tools register from the reviewed manifest (benchmark/manifest.py).

A declaration says
  - how a call becomes Cedar requests (one or more; all must be allowed), or
    that the tool is a source tool (it only brings data in: no policy
    constrains the call, its output is labeled);
  - the minimum integrity level the call needs (level.cedar);
  - the Cedar context the call adds beyond the caller's label (e.g. the
    tool's effect, data confidentiality and egress sink clearance);
  - the label of what the tool returns, joined into the caller's context.

A tool without a declaration is not mediated: every call to it is denied.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from security.labels import Label
from state import Level


@dataclass(frozen=True)
class CedarRequest:
    action: str
    resource_type: str
    resource_id: str
    extra_entities: tuple = ()


Args = Dict[str, Any]


def _bottom(args: Args) -> Label:
    # Confirmations only (a write, a delete, a send): nothing enters the context.
    return Label.bottom()


@dataclass(frozen=True)
class ToolDeclaration:
    name: str
    # args -> Cedar requests; raises ValueError for a call that cannot be
    # mediated (unknown field, missing recipient...), which fails closed.
    requests: Optional[Callable[[Args], list]] = None
    required_level: Level = Level.UNTRUSTED_EXTERNAL
    source: bool = False
    # (args, security context) -> extra Cedar context of the call.
    context: Callable[[Args, Any], dict] = field(default=lambda args, ctx: {})
    output_label: Callable[[Args], Label] = _bottom
    # Cedar schema of the tool's action (engine/schema.py generates it from
    # these): the resource entity type the call authorizes against, and the
    # action groups it joins. A source tool has no action. The action id is the
    # tool name; `tool_call` (grouping every mediated tool) is added by the
    # generator, so grants can gate on it.
    resource_type: str = ""
    action_groups: tuple[str, ...] = ()
    # The system whose schema generates this tool's action (e.g. "benchmark"), so
    # one system's tools never leak into another's schema.
    system: str = ""


def declarations_for(system: str) -> list:
    """Mediated (non-source) tool declarations of one system, for its schema."""
    return [d for d in REGISTRY.values() if d.system == system and d.resource_type]


REGISTRY: dict[str, ToolDeclaration] = {}


def register(*declarations: ToolDeclaration) -> None:
    for declaration in declarations:
        if declaration.name in REGISTRY and REGISTRY[declaration.name] != declaration:
            raise ValueError(f"tool {declaration.name!r} is already declared differently")
        REGISTRY[declaration.name] = declaration


def declaration(tool: str) -> Optional[ToolDeclaration]:
    return REGISTRY.get(tool)


def required_level(tool: str) -> Level:
    d = declaration(tool)
    return d.required_level if d is not None else Level.UNTRUSTED_EXTERNAL


def output_label(tool: str, args: Args) -> Label:
    d = declaration(tool)
    return d.output_label(args) if d is not None else Label.bottom()
