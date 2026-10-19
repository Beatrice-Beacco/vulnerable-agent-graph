// Grants (least privilege): an agent may call a tool only if its system spec
// provisioned that tool for it. The agent carries its provisioned tools
// (engine/crm_system.py -> the Agent entity's `tools`); the call carries the
// tool name (context.tool). One data-driven permit replaces the per-agent
// permits, so a new system's grants are data, not policy.

@id("provisioned-tools")
permit (
  principal,
  action in Action::"tool_call",
  resource
)
when { principal.tools.contains(context.tool) };

// Analysts and the arbiter submit analyses; validation.cedar,
// quarantine.cedar and consensus.cedar restrict which ones are accepted.
@id("analyst-grants")
permit (
  principal in Role::"Analyst",
  action in [Action::"check_analysis", Action::"adopt_analysis"],
  resource
);
