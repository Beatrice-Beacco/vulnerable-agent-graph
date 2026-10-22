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
    return Label.bottom()


@dataclass(frozen=True)
class ToolDeclaration:
    name: str
    requests: Optional[Callable[[Args], list]] = None
    required_level: Level = Level.UNTRUSTED_EXTERNAL
    source: bool = False
    context: Callable[[Args, Any], dict] = field(default=lambda args, ctx: {})
    output_label: Callable[[Args], Label] = _bottom
    resource_type: str = ""
    action_groups: tuple[str, ...] = ()
    system: str = ""


def declarations_for(system: str) -> list:
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
