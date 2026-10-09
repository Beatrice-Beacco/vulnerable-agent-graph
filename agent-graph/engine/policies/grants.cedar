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

// Analysts and the arbiter submit analyses; validation.cedar,
// quarantine.cedar and consensus.cedar restrict which ones are accepted.
@id("analyst-grants")
permit (
  principal in Role::"Analyst",
  action in [Action::"check_analysis", Action::"adopt_analysis"],
  resource
);

