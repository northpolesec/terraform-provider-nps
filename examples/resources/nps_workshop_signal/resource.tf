# A signal that flags reads of Chrome's cookie store by unexpected processes.
resource "nps_workshop_signal" "ChromeCookieAccess" {
  name        = "CRED-001"
  tag         = "global"
  description = "Access to the Chrome cookie store"
  severity    = "HIGH"
  expression  = "event.file.path.endsWith('/Cookies')"
  labels      = ["credentials", "chrome"]

  # The operating system this signal applies to. Defaults to MACOS; hosts
  # running a different OS are sent a removal for the signal instead.
  os_type = "MACOS"

  # Report the whole process tree around the match, not just its ancestry.
  full_process_tree = true
}
