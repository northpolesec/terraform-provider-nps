# A network flow rule that denies outgoing connections from a specific process
# to a remote domain.
resource "nps_workshop_network_flow_rule" "block_spacemolt" {
  name      = "block-spacemolt"
  tag       = "global"
  action    = "NETWORK_FLOW_RULE_ACTION_DENY"
  direction = "NETWORK_FLOW_DIRECTION_OUTGOING"

  process_signing_ids = [
    "Q6L2SF6YDW:com.anthropic.claude-code",
  ]

  remote_domains = [
    "spacemolt.com",
  ]

  comment = "Block claude-code from reaching spacemolt.com."
}
