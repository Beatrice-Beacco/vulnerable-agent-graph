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
