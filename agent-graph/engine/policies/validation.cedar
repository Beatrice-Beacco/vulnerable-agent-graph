// Validation: an analysis turns a request into a CRM operation. It is
// accepted only if it is grounded in the request it was derived from: the
// operation is supported by the words of the request, the customer and the
// recipient are written in it, and the fields the operation does not use are
// empty. These policies are about the analyst, not the request: whether the
// request itself can be trusted is decided by its label.

@id("analysis-operation-in-request")
forbid (
  principal,
  action == Action::"check_analysis",
  resource
)
unless { resource.evidence.containsAny(context.request_words) };

@id("analysis-customer-in-request")
forbid (
  principal,
  action == Action::"check_analysis",
  resource
)
unless { context.request_numbers.contains(context.customer_id) };

@id("analysis-send-shape")
forbid (
  principal,
  action == Action::"check_analysis",
  resource == Operation::"send_customer_data"
)
unless {
  context.field_count > 0 &&
  context.value == "" &&
  context.request_addresses.contains(context.recipient)
};

@id("analysis-update-shape")
forbid (
  principal,
  action == Action::"check_analysis",
  resource == Operation::"update_customer"
)
unless {
  context.field_count == 1 &&
  context.value != "" &&
  context.value_in_request &&
  context.recipient == ""
};

@id("analysis-delete-shape")
forbid (
  principal,
  action == Action::"check_analysis",
  resource == Operation::"delete_customer"
)
unless {
  context.field_count == 0 &&
  context.value == "" &&
  context.recipient == ""
};
