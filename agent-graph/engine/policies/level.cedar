// Security-level requirement (WS1 lattice). Each tool needs a minimum level;
// the monitor sets required_level per tool (reads 0, write INTERNAL, delete
// USER, send 0). A call from a context below that level is denied. The PEP
// treats a denial whose ONLY cause is this policy as escalatable: it asks the
// user, and on approval retries the single call at the required level (WS2).
// It subsumes the old no-untrusted-mutation (a mutation needs >= INTERNAL).

@id("insufficient-level")
forbid (
  principal,
  action in Action::"tool_call",
  resource
)
when { context.level < context.required_level };
