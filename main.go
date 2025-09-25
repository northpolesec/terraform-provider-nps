// Copyright 2025 North Pole Security, Inc.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/northpolesec/terraform-provider-nps/internal/auth"
	"github.com/northpolesec/terraform-provider-nps/internal/provider"
)

var (
	// these will be set by the goreleaser configuration
	// to appropriate values for the compiled binary.
	version string = "dev"

	// goreleaser can pass other information to the main package, such as the specific commit
	// https://goreleaser.com/cookbooks/using-main.version/
)

func main() {
	var debug bool
	var loginServer string

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.StringVar(&loginServer, "login", "", "login to the provider using the specified server")
	flag.Parse()

	// Ordinarily a Terraform provider will only start a providerserver. This provider
	// has a special case for the -login flag that allows the user to login to the
	// Workshop instance and store the token so that the next time the provider runs
	// the token will be available.
	if loginServer != "" {
		if err := auth.GetAndStoreToken(context.Background(), loginServer); err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	opts := providerserver.ServeOpts{
		// TODO: Update this string with the published name of your provider.
		// Also update the tfplugindocs generate command to either remove the
		// -provider-name flag or set its value to the updated provider name.
		Address: "registry.terraform.io/northpolesec/nps",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
