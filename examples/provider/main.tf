terraform {
  required_providers {
    nps = {
      source  = "northpolesec/nps"
      version = "1.0.0"
    }
  }

  required_version = ">= 1.2.0"
}

provider "nps" {
  endpoint = "http://localhost:8080"
}
