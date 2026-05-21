resource "nps_workshop_settings_risk_engine" "settings" {
  enabled        = true
  plugin_timeout = "5s"

  local_plugins = {
    virus_total = {
      enabled           = true
      api_key           = "replace-me"
      cache_ttl         = "30m"
      num_cache_entries = 1000
    }
  }

  remote_plugins = [
    {
      enabled = true
      name    = "house-of-elves"
      version = "1.0.0"
      url     = "https://plugins.north-pole/elves"
      ttl     = "2s"
      secret  = "deadbeefcafef00d"
      headers = [
        {
          key   = "X-Workshop-Tenant"
          value = "north-pole"
        },
      ]
    },
  ]
}
