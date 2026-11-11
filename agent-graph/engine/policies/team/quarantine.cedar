@id("team-quarantine-denied-agent")
forbid (
  principal,
  action in Action::"tool_call",
  resource
)
when { context.denied_tools.contains(context.tool) };
