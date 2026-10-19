"""
Human-in-the-loop escalation (WS2). When a tool call is denied only because
the context level is below what the tool requires (level.cedar), the PEP asks
the user instead of hard-denying. On approval the level is raised for that one
call; reading tainted data afterwards lowers it again.

The user is resolved by USER_POLICY:
  - unset / "interactive": prompt on the console (manual runs).
  - "always_approve": always raise the level.
  - "always_deny": never raise.
  - "informed": use the `informed` callback the caller passed (what a careful
    user who knows the task would do); without one, deny (the safe default).

Only the level check is escalatable; a confidentiality or grant denial is
never offered to the user (enforced by the PEP, which escalates a call only
when raising the level alone would authorize it).
"""

import os

from security import trace


def _ask_console(agent, tool, args, context, required) -> bool:
    print("\n*** ESCALATION REQUEST ***")
    print(f"Agent {agent} wants to call {tool}({args}).")
    print(f"Context level {context.level.name} < required {required.name}.")
    print(f"Provenance of the context: {sorted(context.provenance)}")
    answer = input("Raise the level for this one call? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def resolve(agent, tool, args, context, required, informed=None) -> bool:
    """`informed`, if given, is the informed user's judgement (approve iff the
    call serves the real task); without one, the informed policy denies."""
    policy = os.getenv("USER_POLICY", "").strip().lower()
    if policy == "always_approve":
        granted = True
    elif policy == "always_deny":
        granted = False
    elif policy == "informed":
        granted = informed() if informed is not None else False
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
