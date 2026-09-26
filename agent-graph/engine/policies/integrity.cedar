@id("no-untrusted-mutation")
forbid (
  principal,
  action in Action::"crm_mutation",
  resource
)
unless { context.integrity == 0 };
