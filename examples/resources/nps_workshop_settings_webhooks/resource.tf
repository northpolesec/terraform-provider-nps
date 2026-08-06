# Ephemeral input feeding the write-only signing secret. Its value is never
# stored in Terraform state.
ephemeral "random_password" "webhook_secret" {
  length = 32
}

resource "nps_workshop_settings_webhooks" "settings" {
  audit_events = {
    enabled = true
    url     = "https://example.com/hooks/audit"
    # Write-only: sourced from an ephemeral value, never persisted to state.
    # Bump secret_wo_version whenever the secret changes to force it to be sent.
    secret_wo         = ephemeral.random_password.webhook_secret.result
    secret_wo_version = "1"
    events            = ["AUDIT_EVENT_RULE_UPSERT", "AUDIT_EVENT_RULE_DELETE"]
    headers = [
      { key = "X-Tenant", value = "north-pole" },
    ]
  }

  signal_reports = {
    enabled = true
    url     = "https://example.com/hooks/signals"
    # Regular (state-stored) secret.
    secret = "replace-me"
    states = ["SIGNAL_REPORT_STATE_NEW"]
  }

  software_approvals = {
    enabled = true
    url     = "https://example.com/hooks/approvals"
  }
}
