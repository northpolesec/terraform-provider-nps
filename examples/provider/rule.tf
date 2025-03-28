resource "nps_workshop_rule" "yes" {
  identifier = "platform:com.apple.yes"
  rule_type  = "SIGNINGID"
  policy     = "BLOCKLIST"
  tag        = "global"
}

resource "nps_workshop_rule" "say" {
  identifier = "platform:com.apple.say"
  rule_type  = "SIGNINGID"
  policy     = "CEL"
  tag        = "global"
  cel_expr   = "args = ['say', 'Santa', 'is', 'great']"
}
