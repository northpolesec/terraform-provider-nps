resource "nps_workshop_tag" "production" { name = "production" }
resource "nps_workshop_tag" "engineering" { name = "engineering" }
resource "nps_workshop_tag" "default" { name = "default" }

# The order is authoritative and determines precedence: the first tag has the
# highest priority. When a host carries multiple tags, a setting or rule defined
# in the higher-priority tag wins. Any tag not listed here is not enabled and has
# no effect.
resource "nps_workshop_tag_order" "this" {
  tags = [
    nps_workshop_tag.production.name,
    nps_workshop_tag.engineering.name,
    nps_workshop_tag.default.name,
  ]
}
