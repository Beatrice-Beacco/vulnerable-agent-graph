@id("database-agent-grants")
permit (
  principal == Agent::"DatabaseAgent",
  action in [
    Action::"read_customer",
    Action::"write_customer",
    Action::"delete_customer"
  ],
  resource
);

@id("email-agent-grants")
permit (
  principal == Agent::"EmailAgent",
  action == Action::"send_email",
  resource
);
