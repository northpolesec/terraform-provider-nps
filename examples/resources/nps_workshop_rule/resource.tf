# A global signing ID rule with a CEL policy
resource "nps_workshop_rule" "say" {
  identifier = "platform:com.apple.say"
  rule_type  = "SIGNINGID"
  policy     = "CEL"
  tag        = "global"
  cel_expr   = "args == ['say', 'Santa', 'is', 'great']"
}

# A global blocklist rule that will only be added if it would affect fewer than
# 50 hosts in the previous 30 days.
resource "nps_workshop_rule" "yes" {
  identifier = "platform:com.apple.yes"
  rule_type  = "SIGNINGID"
  policy     = "BLOCKLIST"
  tag        = "global"

  affected_host_threshold {
    days       = 30
    host_count = 50
  }
}
