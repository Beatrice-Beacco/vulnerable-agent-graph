// Quarantine: analysts have no business with CRM or email tools. An analyst
// that attempted a call the monitor denied is compromised, and none of its
// analyses is accepted, however plausible it looks.

@id("quarantine-denied-analyst")
forbid (
  principal,
  action == Action::"check_analysis",
  resource
)
when { context.denied_calls > 0 };
