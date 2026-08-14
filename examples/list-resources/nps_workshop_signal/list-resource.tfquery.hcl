# Query files use the .tfquery.hcl extension and are run with `terraform query`.
# This block lists every signal.
list "nps_workshop_signal" "all" {
  provider = nps

  # Return full resource objects rather than just identities. Useful when you
  # intend to generate import blocks from the results.
  include_resource = true
}
