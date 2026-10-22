from pathlib import Path

from engine.tool_contract import declarations_for

from .cedar_util import entity

POLICY_DIR = Path(__file__).resolve().parent / "policies"


def _tool_action(declaration, context_type: str) -> str:
    groups = [*declaration.action_groups, "tool_call"]
    group_clause = " in [" + ", ".join(f'"{g}"' for g in groups) + "]"
    return (
        f'action "{declaration.name}"{group_clause} appliesTo {{\n'
        f"  principal: Agent,\n"
        f"  resource: {declaration.resource_type},\n"
        f"  context: {context_type},\n"
        f"}};"
    )


def build_schema(core_file: str, system: str, context_type: str) -> str:
    core = (POLICY_DIR / core_file).read_text(encoding="utf-8")
    actions = [_tool_action(d, context_type) for d in declarations_for(system)]
    return core + "\n" + "\n\n".join(actions) + "\n"


def system_entities(system) -> list:
    return [
        *(entity("Role", role) for role in system.roles()),
        *(
            entity(
                "Agent", agent.id, {"tools": list(agent.tools)},
                parents=[("Role", agent.role)] if agent.role else [],
            )
            for agent in system.agents
        ),
    ]
