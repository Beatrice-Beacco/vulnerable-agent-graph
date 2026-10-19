// No write down (Bell-LaPadula) for a team, the context-based counterpart of
// the CRM's resource-based confidentiality.cedar: an egress may not move data
// to a sink cleared below it -- neither the data already in the conversation
// (context.conf) nor the data the tool itself sends (context.data_conf).
// Never escalatable: raising the level does not clear it.

@id("team-no-write-down")
forbid (
  principal,
  action in Action::"tool_call",
  resource
)
when {
  context.effect == "egress" &&
  (context.conf > context.sink_clearance ||
   context.data_conf > context.sink_clearance)
};
