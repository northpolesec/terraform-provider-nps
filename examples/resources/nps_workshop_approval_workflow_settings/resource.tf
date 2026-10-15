# Engineers vote each other's software through.
resource "nps_workshop_approval_workflow_settings" "dev" {
  tag                 = "dev"
  approval_rule_type  = "CDHASH"
  notification_method = "SLACK"

  social_voting {
    local_threshold             = 2
    tag_threshold               = 5
    tags_to_consider_votes_from = ["dev", "sre"]
    require_justification       = true
  }
}

# Everyone else asks the security team, two of whom must agree.
resource "nps_workshop_approval_workflow_settings" "global" {
  tag                 = "global"
  approval_rule_type  = "SIGNINGID"
  notification_method = "SLACK"

  designated_approver {
    approver_tag          = "security"
    threshold             = 2
    chat_channel          = "#santa-approvals"
    require_justification = true
  }
}

# Contractors get no workflow at all: with no workflow block, the global
# workflow above no longer reaches them.
resource "nps_workshop_approval_workflow_settings" "contractors" {
  tag                = "contractors"
  approval_rule_type = "CDHASH"
}
