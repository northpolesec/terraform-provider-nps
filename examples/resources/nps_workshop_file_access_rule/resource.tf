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
}

