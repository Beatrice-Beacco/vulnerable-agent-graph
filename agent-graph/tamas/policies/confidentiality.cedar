// No write down (Bell-LaPadula), as engine/policies/confidentiality.cedar: an
// egress may not move data to a sink cleared below it -- neither data already
// in the conversation (context.conf) nor the data the tool itself sends
// (resource.data_conf). Never escalatable: raising the level does not clear it.

@id("tamas-no-write-down")
forbid (
  principal,
  action == Action::"call",
  resource
)
when {
  resource.effect == "egress" &&
  (context.conf > resource.sink_clearance ||
   resource.data_conf > resource.sink_clearance)
};
