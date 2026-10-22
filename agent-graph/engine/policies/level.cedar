@id("insufficient-level")
forbid (
  principal,
  action in Action::"tool_call",
  resource
)
when { context.level < context.required_level };
