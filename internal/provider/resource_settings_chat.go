// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &ChatSettingsResource{}
var _ resource.ResourceWithConfigure = &ChatSettingsResource{}
var _ resource.ResourceWithImportState = &ChatSettingsResource{}
var _ resource.ResourceWithIdentity = &ChatSettingsResource{}

func NewChatSettingsResource() resource.Resource {
	return &ChatSettingsResource{}
}

type ChatSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type ChatSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type ChatSettingsResourceModel struct {
	Slack types.Object `tfsdk:"slack"`
}

type ChatSettingsSlackModel struct {
	Enabled           types.Bool   `tfsdk:"enabled"`
	Token             types.String `tfsdk:"token"`
	Workspace         types.String `tfsdk:"workspace"`
	UseEmojis         types.Bool   `tfsdk:"use_emojis"`
	HmacSigningSecret types.String `tfsdk:"hmac_signing_secret"`
	UrlRedirectCookie types.String `tfsdk:"url_redirect_cookie"`
}

var chatSlackObjectAttrTypes = map[string]attr.Type{
	"enabled":             types.BoolType,
	"token":               types.StringType,
	"workspace":           types.StringType,
	"use_emojis":          types.BoolType,
	"hmac_signing_secret": types.StringType,
	"url_redirect_cookie": types.StringType,
}

func (r *ChatSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_chat"
}

func (r *ChatSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_chat resource manages chat integration settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",
		MarkdownDescription: "The `nps_workshop_settings_chat` resource manages chat integration settings for Workshop. This is a singleton resource — one per tenant. The initial apply imports any existing values; subsequent applies push the configured values. Destroying the resource removes it from state without modifying the server.",

		Attributes: map[string]schema.Attribute{
			"slack": schema.SingleNestedAttribute{
				Description:         "Slack bot integration settings. Setting this configures the Slack chat type.",
				MarkdownDescription: "Slack bot integration settings. Setting this configures the Slack chat type.",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description:         "Whether the Slack bot is enabled.",
						MarkdownDescription: "Whether the Slack bot is enabled.",
						Optional:            true,
					},
					"token": schema.StringAttribute{
						Description:         "The Slack token for the bot to connect to the workspace. Sensitive.",
						MarkdownDescription: "The Slack token for the bot to connect to the workspace. Sensitive.",
						Optional:            true,
						Sensitive:           true,
					},
					"workspace": schema.StringAttribute{
						Description:         "The Slack workspace to connect to.",
						MarkdownDescription: "The Slack workspace to connect to.",
						Optional:            true,
					},
					"use_emojis": schema.BoolAttribute{
						Description:         "Whether to use emojis in Slack messages.",
						MarkdownDescription: "Whether to use emojis in Slack messages.",
						Optional:            true,
					},
					"hmac_signing_secret": schema.StringAttribute{
						Description:         "The HMAC signing secret for the Slack bot. Sensitive.",
						MarkdownDescription: "The HMAC signing secret for the Slack bot. Sensitive.",
						Optional:            true,
						Sensitive:           true,
					},
					"url_redirect_cookie": schema.StringAttribute{
						Description:         "URL redirect cookie name.",
						MarkdownDescription: "URL redirect cookie name.",
						Optional:            true,
					},
				},
			},
		},
	}
}

func (r *ChatSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	pd, ok := req.ProviderData.(*NPSProviderResourceData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected NPSProviderResourceData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = pd.Client
}

func (r *ChatSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ChatSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	slack, d := chatSlackFromObject(ctx, data.Slack)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if slack != nil {
		upReq := apipb.UpdateChatSettingsRequest_builder{SlackBotSettings: slack}.Build()
		if _, err := r.client.UpdateChatSettings(ctx, upReq); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update chat settings: %v", err))
			return
		}
	}

	tflog.Info(ctx, "Created chat settings resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ChatSettingsIdentityModel{Id: types.StringValue("chat_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ChatSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetChatSettings(ctx, apipb.GetChatSettingsRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get chat settings: %v", err))
		return
	}

	data, d := chatProtoToModel(ctx, ret.GetSlackBotSettings())
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ChatSettingsIdentityModel{Id: types.StringValue("chat_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ChatSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ChatSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// UpdateChatSettings replaces the chat type via oneof. If the plan has
	// no slack block but the state did, we delete; otherwise we push the
	// plan's slack block.
	planSlack, d := chatSlackFromObject(ctx, plan.Slack)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planSlack == nil {
		// User removed the slack block. Delete server-side configuration.
		if !state.Slack.IsNull() {
			delReq := apipb.DeleteChatSettingsRequest_builder{
				ChatType: apipb.DeleteChatSettingsRequest_CHAT_TYPE_SLACK.Enum(),
			}.Build()
			if _, err := r.client.DeleteChatSettings(ctx, delReq); err != nil {
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to delete chat settings: %v", err))
				return
			}
			tflog.Info(ctx, "Deleted chat settings")
		}
	} else {
		upReq := apipb.UpdateChatSettingsRequest_builder{
			SlackBotSettings: planSlack,
		}.Build()
		if _, err := r.client.UpdateChatSettings(ctx, upReq); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to update chat settings: %v", err))
			return
		}
		tflog.Info(ctx, "Updated chat settings")
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, ChatSettingsIdentityModel{Id: types.StringValue("chat_settings")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ChatSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed chat settings from Terraform state (server-side configuration unchanged)")
}

func (r *ChatSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &ChatSettingsResourceModel{
		Slack: types.ObjectNull(chatSlackObjectAttrTypes),
	})...)
}

func (r *ChatSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func chatProtoToModel(ctx context.Context, s *apipb.SlackBotSettings) (ChatSettingsResourceModel, diag.Diagnostics) {
	if s == nil {
		return ChatSettingsResourceModel{
			Slack: types.ObjectNull(chatSlackObjectAttrTypes),
		}, nil
	}
	obj, d := types.ObjectValue(chatSlackObjectAttrTypes, map[string]attr.Value{
		"enabled":             boolPtrToTF(s.Enabled),
		"token":               stringPtrToTF(s.Token),
		"workspace":           stringPtrToTF(s.Workspace),
		"use_emojis":          boolPtrToTF(s.UseEmojis),
		"hmac_signing_secret": stringPtrToTF(s.HmacSigningSecret),
		"url_redirect_cookie": stringPtrToTF(s.UrlRedirectCookie),
	})
	return ChatSettingsResourceModel{Slack: obj}, d
}

func chatSlackFromObject(ctx context.Context, obj types.Object) (*apipb.SlackBotSettings, diag.Diagnostics) {
	if obj.IsNull() || obj.IsUnknown() {
		return nil, nil
	}
	var m ChatSettingsSlackModel
	d := obj.As(ctx, &m, basetypes.ObjectAsOptions{})
	if d.HasError() {
		return nil, d
	}
	return apipb.SlackBotSettings_builder{
		Enabled:           tfBoolToPtr(m.Enabled),
		Token:             tfStringToPtr(m.Token),
		Workspace:         tfStringToPtr(m.Workspace),
		UseEmojis:         tfBoolToPtr(m.UseEmojis),
		HmacSigningSecret: tfStringToPtr(m.HmacSigningSecret),
		UrlRedirectCookie: tfStringToPtr(m.UrlRedirectCookie),
	}.Build(), nil
}
