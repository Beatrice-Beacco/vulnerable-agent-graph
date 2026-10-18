// Security-level requirement (WS1 lattice), as engine/policies/level.cedar.
// Each tool needs a minimum level by its effect (tamas/effects.py: read 0,
// write and egress INTERNAL, critical USER). A call from a context below it is
// denied; the PEP treats a denial whose only cause is this policy as
// escalatable and asks the user (WS2).

@id("tamas-insufficient-level")
forbid (
  principal,
  action == Action::"call",
  resource
)
when { context.level < resource.required_level };
