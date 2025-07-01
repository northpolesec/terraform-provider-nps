resource "nps_workshop_apikey" "key" {
  name = "testytest"
  permissions = [
    "read:hosts",
    "write:hosts",
  ]
}
