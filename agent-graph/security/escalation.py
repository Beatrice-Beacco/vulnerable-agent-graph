import os

from security import trace


def _ask_console(agent, tool, args, context, required) -> bool:
    print("\n*** ESCALATION REQUEST ***")
    print(f"Agent {agent} wants to call {tool}({args}).")
    print(f"Context level {context.level.name} < required {required.name}.")
    print(f"Provenance of the context: {sorted(context.provenance)}")
    answer = input("Raise the level for this one call? [y/N] ").strip().lower()
    return answer in ("y", "yes")


_informed_user = None


def set_informed_user(judge) -> None:
    global _informed_user
    _informed_user = judge


def resolve(agent, tool, args, context, required, informed=None) -> bool:
    policy = os.getenv("USER_POLICY", "").strip().lower()
    if policy == "always_approve":
        granted = True
    elif policy == "always_deny":
        granted = False
    elif policy == "informed":
        judge = informed or _informed_user
        granted = bool(judge(agent, tool, args)) if judge is not None else False
    else:
        granted = _ask_console(agent, tool, args, context, required)

    print(f"ESCALATION {agent} -> {tool}: {'GRANTED' if granted else 'DENIED'} "
          f"(policy={policy or 'interactive'})")
    trace.event(
        "escalation",
        agent=agent,
        tool=tool,
        args=dict(args),
        context_level=context.level.name,
        required_level=required.name,
        provenance=sorted(context.provenance),
        policy=policy or "interactive",
        granted=granted,
    )
    return granted
