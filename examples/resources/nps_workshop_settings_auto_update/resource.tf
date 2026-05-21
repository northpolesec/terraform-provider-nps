resource "nps_workshop_settings_auto_update" "settings" {
  mode       = "AUTO_UPDATE_MODE_ENABLED_SECURITY_ONLY"
  start_hour = 20
  end_hour   = 5
}
