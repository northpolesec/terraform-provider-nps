# Subscribe to a pack, naming it by its title as shown in the Workshop rule
# pack catalog. Workshop allows only one subscription per pack, so every tag
# the pack should apply to is listed here rather than in a second resource.
resource "nps_workshop_rule_pack_subscription" "cryptojacking" {
  rule_pack_title = "Block Cryptojacking"
  tags            = ["production", "canary"]

  # Optional. Set this to the subscription's latest_commit_sha once you have
  # reviewed that version of the pack, and Terraform will apply the update.
  # Leave it out and Terraform never changes the materialized version.
  commit_sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
}

# Naming the pack by UUID avoids a catalog lookup at plan time.
resource "nps_workshop_rule_pack_subscription" "password_hash_dumping" {
  rule_pack_id = "890f3fb2-9f8c-412d-af04-b0636a94ebae"
  tags         = ["global"]
}
