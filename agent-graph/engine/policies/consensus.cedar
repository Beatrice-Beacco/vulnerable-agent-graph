// Consensus: an analysis becomes the operation the executors run only if no
// other checked analysis of the same request describes a different
// operation. Conflicting grounded analyses mean at least one analyst is
// wrong or compromised: the request needs a human.

@id("consensus")
forbid (
  principal,
  action == Action::"adopt_analysis",
  resource
)
when { context.conflicting_analyses > 0 };
