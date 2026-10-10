// Data-subject routing: a request that came from outside (untrusted) may only
// send a customer's data to that customer's own registered address. A
// recipient the request merely names -- a fallback or alternative planted in
// an external email -- is not the data subject and is refused. Closes the
// recipient-redirect gap for low-sensitivity data the confidentiality lattice
// does not protect. Internal (trusted) requests are unaffected.

@id("external-send-to-data-subject-only")
forbid (
  principal,
  action == Action::"send_email",
  resource
)
when { context.integrity != 0 }
unless { context.recipient_is_customer_contact };
