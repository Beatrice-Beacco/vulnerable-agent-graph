"""
Builds a Cedar schema for a system from a schema core (the entity and context
types, the action groups) plus one action per mediated tool, generated from the
tool registry (engine/tool_contract.py). The agents and their granted tools
come from the system spec (engine/system.py). Nothing here is tied to a
particular system: a system supplies its core schema file, its tool
declarations and its spec.
"""

from pathlib import Path

from engine.tool_contract import declarations_for

from .cedar_util import entity  # noqa: F401 -- re-exported for callers

POLICY_DIR = Path(__file__).resolve().parent / "policies"


def _tool_action(declaration, context_type: str) -> str:
    """The Cedar action declaration of one mediated tool. Every mediated tool
    joins the `tool_call` group, so the data-driven grant can gate on it."""
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
    """A schema core plus one action per mediated tool of `system`."""
    core = (POLICY_DIR / core_file).read_text(encoding="utf-8")
    actions = [_tool_action(d, context_type) for d in declarations_for(system)]
    return core + "\n" + "\n\n".join(actions) + "\n"


def system_entities(system) -> list:
    """The Cedar entities of a system's agents: its roles, and one Agent per
    agent carrying its provisioned tools and its role."""
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
