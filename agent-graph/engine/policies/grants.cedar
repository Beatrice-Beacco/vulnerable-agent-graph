// Grants (least privilege): an agent may call a tool only if its system spec
// provisioned that tool for it. The agent carries its provisioned tools
// (engine/schema.system_entities -> the Agent entity's `tools`); the call
// carries the tool name (context.tool). One data-driven permit replaces the
// per-agent permits, so a new system's grants are data, not policy.

@id("provisioned-tools")
permit (
  principal,
  action in Action::"tool_call",
  resource
)
when { principal.tools.contains(context.tool) };
