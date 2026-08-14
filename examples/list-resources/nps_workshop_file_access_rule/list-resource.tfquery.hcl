# Query files use the .tfquery.hcl extension and are run with `terraform query`.
# This block lists every file access rule.
list "nps_workshop_file_access_rule" "all" {
  provider = nps

  # Terraform returns 100 results per list block by default. Raise `limit` to
  # cover a larger instance.
  limit = 1000

  # Return full resource objects rather than just identities. Useful when you
  # intend to generate import blocks from the results.
  include_resource = true
}
