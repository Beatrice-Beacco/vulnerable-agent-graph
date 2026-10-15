@id("no-untrusted-confidential-read")
forbid (
  principal,
  action == Action::"read_customer",
  resource
)
when { context.level < 2 && resource.classification >= 2 };
