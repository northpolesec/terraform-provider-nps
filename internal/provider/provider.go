// Copyright 2024 North Pole Security, Inc.

package provider

import (
	"context"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
	Client   *http.Client
	Endpoint string
}

func (p *NPSProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nps"
	resp.Version = p.version
}

func (p *NPSProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "The base URL for the Workshop instance. Can also be supplied using the NPS_ENDPOINT envrionment variable.",
				Optional:    true,
			},
			"api_key": schema.StringAttribute{
				Description: "The API key to use. Can also be supplied using the NPS_API_KEY environment variable.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

type withHeader struct {
	http.Header
	rt http.RoundTripper
}

func WithHeader(rt http.RoundTripper) withHeader {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return withHeader{Header: make(http.Header), rt: rt}
}

func (h withHeader) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(h.Header) == 0 {
		return h.rt.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	for k, v := range h.Header {
		req.Header[k] = v
	}
	return h.rt.RoundTrip(req)
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

	// Validate API key
	apiKey := data.APIKey.ValueString()
	if e := os.Getenv("NPS_API_KEY"); e != "" {
		apiKey = e
	}
	if apiKey == "" {
		resp.Diagnostics.AddError("NPS Provider configuration error", "api_key (or NPS_API_KEY environment variable) must be set")
		return
	}

	client := http.DefaultClient
	rt := WithHeader(client.Transport)
	rt.Set("Authorization", apiKey)
	rt.Set("User-Agent", "terraform-provider-nps")
	client.Transport = rt

	resp.DataSourceData = client
	resp.ResourceData = &NPSProviderResourceData{
		Client:   client,
		Endpoint: endpoint,
	}
}

func (p *NPSProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRuleResource,
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
