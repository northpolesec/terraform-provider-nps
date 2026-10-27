# A network flow rule that denies outgoing connections from a specific process
# to a remote domain.
resource "nps_workshop_network_flow_rule" "block_spacemolt" {
  name      = "block-spacemolt"
  tag       = "global"
  action    = "DENY"
  direction = "OUTGOING"

  process_signing_ids = [
    "Q6L2SF6YDW:com.anthropic.claude-code",
  ]

  remote_domains = [
    "spacemolt.com",
  ]

  comment = "Block claude-code from reaching spacemolt.com."
}

# A DNS rule that blocks lookups of a domain and every name under it on all
# hosts in the tag. Requires Workshop 2026.9 or later.
resource "nps_workshop_network_flow_rule" "sinkhole_spacemolt" {
  name         = "sinkhole-spacemolt"
  tag          = "global"
  kind         = "DNS"
  action       = "DENY"
  dns_response = "NXDOMAIN"

  remote_domains = [
    "spacemolt.com",
  ]
}
