resource "nps_workshop_settings_export_config" "settings" {
  audit_event_bucket_url       = "gs://north-pole-audit-events"
  execution_event_bucket_url   = "gs://north-pole-execution-events"
  file_access_event_bucket_url = "gs://north-pole-file-access-events"
}
