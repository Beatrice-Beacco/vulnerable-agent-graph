// Grants (least privilege) as a single global whitelist: an agent may call a
// tool only if that tool is on the whitelist. The whitelist is one global list
// (benchmark/catalog.WHITELIST), the same for every agent, surfaced per call as
// context.whitelisted (benchmark/manifest.py). A tool not on the whitelist is
// denied for every agent. The over-provisioning ablation sets every tool
// whitelisted (WHITELIST_ALL=1), so the grant permits all and only the lattice
// defends.

@id("whitelisted-tool")
permit (
  principal,
  action in Action::"tool_call",
  resource
)
when { context.whitelisted };
