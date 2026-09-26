@id("no-write-down-email")
forbid (
  principal,
  action == Action::"send_email",
  resource
)
when { context.conf > resource.clearance };

@id("no-write-down-field")
forbid (
  principal,
  action == Action::"write_customer",
  resource
)
when { context.conf > resource.classification };
