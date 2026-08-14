# Query files use the .tfquery.hcl extension and are run with `terraform query`.
# This block lists every network flow rule.
list "nps_workshop_network_flow_rule" "all" {
  provider = nps

  # Return full resource objects rather than just identities. Useful when you
  # intend to generate import blocks from the results.
  include_resource = true
}
