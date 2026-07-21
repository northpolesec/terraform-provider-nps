resource "nps_workshop_settings_apikey_cidr" "settings" {
  enabled = true
  allowed_cidrs = [
    "10.0.0.0/8",
    "192.168.1.0/24",
  ]
}
