resource "nps_workshop_settings_sync_auth" "settings" {
  enable_mtls_auth  = true
  enable_token_auth = true
  sync_tokens = [
    "replace-me-1",
    "replace-me-2",
  ]
}
