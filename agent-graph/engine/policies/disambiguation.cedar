// Disambiguation: a destructive operation (delete) must come from a request
// that unambiguously calls for it. If the request also supports another
// operation, no single analysis can authorize the deletion -- the request is
// ambiguous and needs a human. Closes the multi-operation gap, where a
// deletion rides a stray supporting word in an otherwise benign request.

@id("no-destructive-from-ambiguous-request")
forbid (
  principal,
  action == Action::"adopt_analysis",
  resource == Operation::"delete_customer"
)
when { context.operations_in_request > 1 };
