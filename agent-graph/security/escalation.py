"""
Human-in-the-loop escalation (WS2). When a tool call is denied only because
the context level is below what the tool requires (level.cedar), the PEP asks
the user instead of hard-denying. On approval the level is raised for that one
call; reading tainted data afterwards lowers it again.

The user is resolved by USER_POLICY:
  - unset / "interactive": prompt on the console (manual runs).
  - "always_approve": always raise the level.
  - "always_deny": never raise.
  - "informed": approve iff the action serves the user's real task, i.e. the
    bound operation matches the scenario's benign_operation (and customer).
    Without a benign_operation, approve iff no agent is compromised.

Only the level check is escalatable; a confidentiality or grant denial is
never offered to the user (enforced by the PEP, which escalates a call only
when raising the level alone would authorize it).
"""

import os

import attacks
from security import trace


def _ask_console(agent, tool, args, context, required) -> bool:
    print("\n*** ESCALATION REQUEST ***")
    print(f"Agent {agent} wants to call {tool}({args}).")
    print(f"Context level {context.level.name} < required {required.name}.")
    print(f"Provenance of the context: {sorted(context.provenance)}")
    answer = input("Raise the level for this one call? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def _informed(context) -> bool:
    scenario = attacks.ACTIVE
    if scenario is None:
        return False
    benign_op = getattr(scenario, "benign_operation", "")
    if benign_op:
        benign_customer = getattr(scenario, "benign_customer", "") or context.binding.customer
        return (
            context.binding.operation == benign_op
            and context.binding.customer == benign_customer
        )
    # No declared benign operation: approve only a genuinely benign run (no
    # attack at all); an input attack (dpi/ipi/...) has no compromised agent
    # but is still not legitimate.
    return scenario.attack == "none"


def resolve(agent, tool, args, context, required) -> bool:
    policy = os.getenv("USER_POLICY", "").strip().lower()
    if policy == "always_approve":
        granted = True
    elif policy == "always_deny":
        granted = False
    elif policy == "informed":
        granted = _informed(context)
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
