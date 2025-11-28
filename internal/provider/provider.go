// Copyright 2025 North Pole Security, Inc.

// Package provider is the NPS provider
package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/northpolesec/terraform-provider-nps/internal/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	apipb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
)

// Ensure ScaffoldingProvider satisfies various provider interfaces.
var _ provider.Provider = &NPSProvider{}
var _ provider.ProviderWithFunctions = &NPSProvider{}

// NPSProvider defines the provider implementation.
type NPSProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// NPSProviderModel describes the provider data model.
type NPSProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIKey   types.String `tfsdk:"api_key"`
}

type NPSProviderResourceData struct {
	Client apipb.WorkshopServiceClient
}

func (p *NPSProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nps"
	resp.Version = p.version
}

func (p *NPSProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "The base URL for the Workshop instance. Can also be supplied using the `WORKSHOP_ENDPOINT` envrionment variable.",
				Optional:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "The API key to use. Can also be supplied using the `WORKSHOP_API_KEY` environment variable. If no API key is provided, the provider will attempt to use a stored short-lived user token.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *NPSProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data NPSProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate endpoint
	endpoint := data.Endpoint.ValueString()
	if e := os.Getenv("NPS_ENDPOINT"); e != "" {
		endpoint = e
	}
	if endpoint == "" {
		resp.Diagnostics.AddError("NPS Provider configuration error", "endpoing (or NPS_ENDPOINT environment variable) must be set")
		return
	}

	// Get the necessary auth call option.
	rpcCreds, err := auth.APIKeyOrToken(ctx, data.APIKey.ValueString(), endpoint)
	if err != nil {
		resp.Diagnostics.AddError("NPS Provider Authentication error", err.Error())
		return
	}

	opts := []grpc.DialOption{grpc.WithPerRPCCredentials(rpcCreds)}

	// If the endpoint is localhost, allow an insecure connection.
	// Otherwise ensure TLS is used.
	if data.Endpoint.ValueString() == "localhost:8080" {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	// Create a new gRPC client for Workshop
	conn, err := grpc.NewClient(fmt.Sprintf("dns:%s", endpoint), opts...)
	if err != nil {
		resp.Diagnostics.AddError("NPS Provider configuration error", fmt.Sprintf("Failed to connect to endpoint: %v", err))
		return
	}
	client := apipb.NewWorkshopServiceClient(conn)

	resp.DataSourceData = client
	resp.ResourceData = &NPSProviderResourceData{
		Client: client,
	}
}

func (p *NPSProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAPIKeyResource,
		NewFileAccessRuleResource,
		NewRuleResource,
		NewTagResource,
	}
}

func (p *NPSProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *NPSProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &NPSProvider{
			version: version,
		}
	}
}
