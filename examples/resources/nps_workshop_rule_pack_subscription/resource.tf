# Subscribe to a pack, naming it by its title as shown in the Workshop rule
# pack catalog. Workshop allows only one subscription per pack, so every tag
# the pack should apply to is listed here rather than in a second resource.
resource "nps_workshop_rule_pack_subscription" "cryptojacking" {
  rule_pack_title = "Block Cryptojacking"
  tags            = ["production", "canary"]

  # Optional, and left unset here so this example applies as-is: with no
  # commit_sha, Terraform never changes the materialized pack version. To adopt
  # an update, read the subscription's latest_commit_sha, review that version of
  # the pack, then pin the SHA you reviewed:
  #
  #   commit_sha = "d63f5160cd000d388dee57bed9edbb120d8e0e16"
  #
  # It must be the currently published version; an older SHA is rejected rather
  # than silently downgraded.
}

# Naming the pack by UUID avoids a catalog lookup at plan time.
resource "nps_workshop_rule_pack_subscription" "password_hash_dumping" {
  rule_pack_id = "890f3fb2-9f8c-412d-af04-b0636a94ebae"
  tags         = ["global"]
}
