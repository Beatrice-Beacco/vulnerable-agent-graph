@id("no-untrusted-confidential-read")
forbid (
  principal,
  action == Action::"read_customer",
  resource
)
when { context.integrity != 0 && resource.classification >= 2 };
