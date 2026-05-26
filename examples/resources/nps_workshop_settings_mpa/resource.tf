resource "nps_workshop_settings_mpa" "settings" {
  enabled            = true
  max_duration       = "24h"
  required_approvers = 2
  exclude_api_keys   = true
}
