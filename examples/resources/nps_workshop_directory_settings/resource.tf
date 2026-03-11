# Directory sync settings with group filter
resource "nps_workshop_tag" "engineering" {
  name = "engineering"
}

resource "nps_workshop_tag" "production" {
  name = "production"
}

resource "nps_workshop_directory_settings" "settings" {
  directory_type = "DIRECTORY_TYPE_DSYNC"

  directory_sync_group_filter {
    id   = "group-1"
    tags = [nps_workshop_tag.engineering.name, nps_workshop_tag.production.name]
  }
}
