resource "nps_workshop_sync_settings" "dev_settings" {
  tag = "dev"

  client_mode = "MONITOR"

  # Set to an empty string to explicitly clear a value inherited from a
  # lower-precedence tag. Omit the attribute entirely to leave it unset.
  allowed_path_regex = ""
  blocked_path_regex = ""

  cel_fallback_rule {
    expression = <<-EOT
      target.entitlements.exists(
        k, k == 'com.apple.security.hypervisor' || k == 'com.apple.security.virtualization'
      ) ? BLOCKLIST : UNSPECIFIED
    EOT
    custom_msg = "No hypervisors!"
  }

  push_sync_interval = 300

  telemetry_enabled = true
  telemetry_filter_expressions = [
    "has(event.Execution) && event.Execution.Envs.exists(e, e.startsWith('GITHUB_TOKEN') && hash(e, 'GITHUB_TOKEN=(.*)'))"
  ]
}
