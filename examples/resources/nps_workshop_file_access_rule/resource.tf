# A file access rule that only allows specific processes to access certain paths
resource "nps_workshop_file_access_rule" "ChromeCookies" {
  name              = "ChomeCookies"
  tag               = "global"
  rule_type         = "PathsWithAllowedProcesses"
  allow_read_access = false
  block_violations  = true

  path_prefixes = [
    "/Users/*/Library/Application Support/Google/Chrome/*/Cookies",
  ]

  process_signing_ids = [
    "EQHXZ8M8AV:com.google.Chrome*"
  ]

  # Chrome is one of the allowed processes above, but audit its access rather
  # than allowing it silently. Every attribute left out of an override entry
  # inherits the rule's own value.
  process_overrides = [
    {
      type   = "SIGNING_ID"
      value  = "EQHXZ8M8AV:com.google.Chrome*"
      action = "AUDIT"
    },
  ]
}
