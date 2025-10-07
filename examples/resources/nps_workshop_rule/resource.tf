# A global signing ID rule with a CEL policy
resource "nps_workshop_rule" "say" {
  identifier = "platform:com.apple.say"
  rule_type  = "SIGNINGID"
  policy     = "CEL"
  tag        = "global"
  cel_expr   = "args == ['say', 'Santa', 'is', 'great']"
}
