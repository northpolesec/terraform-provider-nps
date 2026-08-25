# Allowlist a set of Homebrew formulae for the engineering tag. Package rules
# sync identifiers from the package catalog, so you name the package rather
# than hashing every binary yourself.
locals {
  engineering_formulae = ["wget", "jq", "ripgrep"]
}

resource "nps_workshop_package_rule" "engineering_homebrew" {
  for_each = toset(local.engineering_formulae)

  # The tag must already exist in Workshop. It also has no effect until it is
  # added to nps_workshop_tag_order.
  tag    = "engineering"
  source = "HOMEBREW"
  name   = each.value

  policy = "ALLOWLIST"

  # The broadest type available for the package, falling back to narrower
  # types when the preferred one is not published.
  rule_type = "TEAMID"
}

# Constrain a rule to a version range: only 1.x versions released after
# 2025-01-01 are covered by this rule.
resource "nps_workshop_package_rule" "engineering_terraform" {
  tag    = "engineering"
  source = "HOMEBREW"
  name   = "terraform"

  policy    = "ALLOWLIST"
  rule_type = "TEAMID"

  min_date       = "2025-01-01T00:00:00Z"
  version_regexp = "^1\\."
}
