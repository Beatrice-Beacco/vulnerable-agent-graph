// Quarantine for a team, the tool-call counterpart of the CRM's
// quarantine.cedar (which gates analyses): an agent that already made a call
// the monitor denied -- a rejected escalation, a confidentiality or grant
// violation -- is treated as compromised, and none of its further tool calls
// is accepted for the rest of the run.

@id("team-quarantine-denied-agent")
forbid (
  principal,
  action in Action::"tool_call",
  resource
)
when { context.agent_denied > 0 };
