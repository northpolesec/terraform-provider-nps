# A signal that flags reads of Chrome's cookie store by unexpected processes.
resource "nps_workshop_signal" "ChromeCookieAccess" {
  name        = "CRED-001"
  tag         = "global"
  description = "Access to the Chrome cookie store"
  severity    = "SEVERITY_HIGH"
  expression  = "event.file.path.endsWith('/Cookies')"
  labels      = ["credentials", "chrome"]
}
