@id("whitelisted-tool")
permit (
  principal,
  action in Action::"tool_call",
  resource
)
when { resource.all || resource.tools.contains(context.tool) };
