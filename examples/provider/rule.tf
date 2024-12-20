resource "nps_workshop_rule" "yes" {
  identifier = "platform:com.apple.yes"
  rule_type  = "SIGNINGID"
  policy     = "BLOCKLIST"
}
