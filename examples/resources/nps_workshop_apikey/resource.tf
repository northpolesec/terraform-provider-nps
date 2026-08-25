# Permissions are verb:resource strings. The key secret is returned as a
# computed attribute and will appear in Terraform state.
resource "nps_workshop_apikey" "ci" {
  name = "ci-pipeline"
  permissions = [
    "read:hosts",
    "write:hosts",
  ]
}
