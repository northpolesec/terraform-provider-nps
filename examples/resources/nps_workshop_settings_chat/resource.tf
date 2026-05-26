resource "nps_workshop_settings_chat" "settings" {
  slack = {
    enabled             = true
    token               = "xoxb-replace-me"
    workspace           = "north-pole"
    use_emojis          = true
    hmac_signing_secret = "replace-me"
  }
}
