// Operation binding: an executor agent may only make the calls that execute
// the operation it was asked for, on the customer, fields, value and
// recipient of the request. The operation is set by the graph node from the
// state, not by the agent's LLM: a compromised executor cannot add operations
// of its own (e.g. a delete after the requested read).

@id("bind-read-customer")
forbid (
  principal,
  action == Action::"read_customer",
  resource
)
unless {
  context.operation == "send_customer_data" &&
  context.call_customer == context.target_customer &&
  context.requested_fields.contains(resource.name)
};

@id("bind-write-customer")
forbid (
  principal,
  action == Action::"write_customer",
  resource
)
unless {
  context.operation == "update_customer" &&
  context.call_customer == context.target_customer &&
  context.requested_fields.contains(resource.name) &&
  context.call_value == context.requested_value
};

@id("bind-delete-customer")
forbid (
  principal,
  action == Action::"delete_customer",
  resource
)
unless {
  context.operation == "delete_customer" &&
  context.call_customer == context.target_customer
};

@id("bind-send-email")
forbid (
  principal,
  action == Action::"send_email",
  resource
)
unless {
  context.operation == "send_customer_data" &&
  context.call_recipient == context.requested_recipient
};
