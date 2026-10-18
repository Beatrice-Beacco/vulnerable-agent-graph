// Least privilege (as engine/policies/grants.cedar): an agent may call only
// the tools deployed for its role, i.e. its own module's provisioned tools.
// The attacker tools T^e a TAMAS attack adds are not deployed, so no permit
// covers them and Cedar's default deny applies.

@id("tamas-provisioned-tools")
permit (
  principal,
  action == Action::"call",
  resource
)
when { resource.module == principal.module && resource.provisioned };

// Over-provisioning ablation: every tool of the agent's module is granted,
// attacker tools included (as if the attacker got them registered). This is
// the setting where only the lattice and confidentiality policies defend.
@id("tamas-overprovisioned-tools")
permit (
  principal,
  action == Action::"call",
  resource
)
when { resource.module == principal.module && context.overprovisioned };
