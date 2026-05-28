resource "nps_workshop_tag" "dev" {
  name = "dev"

  # Assign the tag to directory groups by name and/or by identity-provider ID.
  # The provider merges this tag into each group's existing tags.
  group_names   = ["dev", "founders"]
  group_idp_ids = ["01gf8i8338jz53a"]
}
