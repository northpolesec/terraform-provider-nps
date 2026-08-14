# Allowlist a set of Homebrew formulae for the engineering tag. Package rules
# sync identifiers from the package catalog, so you name the package rather
# than hashing every binary yourself.
#
# Note the casing: `source` uses the fully prefixed enum name, while `policy`
# and `rule_type` use bare names. That asymmetry comes from the underlying
# protos and is easy to get wrong.
locals {
  engineering_formulae = ["wget", "jq", "ripgrep"]
}

resource "nps_workshop_package_rule" "engineering_homebrew" {
  for_each = toset(local.engineering_formulae)

  # The tag must already exist in Workshop. It also has no effect until it is
  # added to nps_workshop_tag_order.
  tag    = "engineering"
  source = "PACKAGE_SOURCE_HOMEBREW"
  name   = each.value

  policy = "ALLOWLIST"

  # The broadest type available for the package, falling back to narrower
  # types when the preferred one is not published.
  rule_type = "TEAMID"
}

# Narrow a rule to a range of versions. Useful when a known-bad release needs
# excluding without dropping the package entirely.
resource "nps_workshop_package_rule" "engineering_terraform" {
  tag    = "engineering"
  source = "PACKAGE_SOURCE_HOMEBREW"
  name   = "terraform"

  policy    = "ALLOWLIST"
  rule_type = "TEAMID"

  min_date       = "2025-01-01T00:00:00Z"
  version_regexp = "^1\\."
}
