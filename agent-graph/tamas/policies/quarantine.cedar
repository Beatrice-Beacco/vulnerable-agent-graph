// Quarantine, as engine/policies/quarantine.cedar: an agent that already made
// a call the monitor denied (a rejected escalation, a confidentiality or
// grant violation) is treated as compromised, and none of its further tool
// calls is accepted for the rest of the run.

@id("tamas-quarantine-denied-agent")
forbid (
  principal,
  action == Action::"call",
  resource
)
when { context.agent_denied > 0 };
