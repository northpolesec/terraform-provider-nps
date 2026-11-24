// Copyright 2026 North Pole Security, Inc.
package provider

import (
	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"net"
	"strings"
	"sync"
	"testing"
)

type settingsSecretServer struct {
	svcpb.UnimplementedWorkshopServiceServer
	mu       sync.Mutex
	chat     *apipb.SlackBotSettings
	risk     *apipb.RiskEngineSettings
	webhooks *apipb.WebhookSettings
}

func hiddenSecret(value string) string {
	if strings.HasPrefix(value, "gcp://") || strings.HasPrefix(value, "aws://") {
		return value
	}
	return ""
}

func hideHeaders(headers []*apipb.HTTPHeader) {
	for _, h := range headers {
		h.SetValue(hiddenSecret(h.GetValue()))
	}
}

func (s *settingsSecretServer) GetChatSettings(context.Context, *apipb.GetChatSettingsRequest) (*apipb.GetChatSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var chat *apipb.SlackBotSettings
	if s.chat != nil {
		chat = proto.Clone(s.chat).(*apipb.SlackBotSettings)
		chat.SetToken(hiddenSecret(chat.GetToken()))
		chat.SetHmacSigningSecret(hiddenSecret(chat.GetHmacSigningSecret()))
	}
	return apipb.GetChatSettingsResponse_builder{SlackBotSettings: chat}.Build(), nil
}

func (s *settingsSecretServer) UpdateChatSettings(_ context.Context, req *apipb.UpdateChatSettingsRequest) (*apipb.UpdateChatSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chat = proto.Clone(req.GetSlackBotSettings()).(*apipb.SlackBotSettings)
	return apipb.UpdateChatSettingsResponse_builder{}.Build(), nil
}

func (s *settingsSecretServer) GetRiskEngineSettings(context.Context, *apipb.GetRiskEngineSettingsRequest) (*apipb.GetRiskEngineSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var risk *apipb.RiskEngineSettings
	if s.risk != nil {
		risk = proto.Clone(s.risk).(*apipb.RiskEngineSettings)
		local := risk.GetLocalPlugins()
		if vt := local.GetVirusTotal(); vt != nil {
			vt.SetApiKey(hiddenSecret(vt.GetApiKey()))
		}
		if rl := local.GetReversingLabs(); rl != nil {
			rl.SetPassword(hiddenSecret(rl.GetPassword()))
		}
		for _, plugin := range risk.GetRemotePlugins() {
			plugin.SetSecret(hiddenSecret(plugin.GetSecret()))
			hideHeaders(plugin.GetHeaders())
		}
	}
	return apipb.GetRiskEngineSettingsResponse_builder{RiskEngineSettings: risk}.Build(), nil
}

func (s *settingsSecretServer) UpdateRiskEngineSettings(_ context.Context, req *apipb.UpdateRiskEngineSettingsRequest) (*apipb.UpdateRiskEngineSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.risk = proto.Clone(req.GetRiskEngineSettings()).(*apipb.RiskEngineSettings)
	return apipb.UpdateRiskEngineSettingsResponse_builder{}.Build(), nil
}

func (s *settingsSecretServer) GetWebhookSettings(context.Context, *apipb.GetWebhookSettingsRequest) (*apipb.GetWebhookSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var settings *apipb.WebhookSettings
	if s.webhooks != nil {
		settings = proto.Clone(s.webhooks).(*apipb.WebhookSettings)
		for _, basic := range []*apipb.WebhookBasicConfig{settings.GetAuditEvents().GetBasic(), settings.GetSignalReports().GetBasic(), settings.GetSoftwareApprovals().GetBasic()} {
			if basic != nil {
				basic.SetSecret("")
				hideHeaders(basic.GetHeaders())
			}
		}
	}
	return apipb.GetWebhookSettingsResponse_builder{Settings: settings}.Build(), nil
}

func (s *settingsSecretServer) UpdateWebhookSettings(_ context.Context, req *apipb.UpdateWebhookSettingsRequest) (*apipb.UpdateWebhookSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks = proto.Clone(req.GetSettings()).(*apipb.WebhookSettings)
	return apipb.UpdateWebhookSettingsResponse_builder{}.Build(), nil
}

func TestSettingsSecretsPlan(t *testing.T) {
	t.Setenv("WORKSHOP_API_KEY", "")
	for _, kind := range []string{"chat", "risk_engine", "webhooks"} {
		t.Run(kind, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			api := &settingsSecretServer{}
			svcpb.RegisterWorkshopServiceServer(server, api)
			t.Cleanup(server.Stop)
			go func() { _ = server.Serve(listener) }()
			endpoint := fmt.Sprintf("localhost:%d", listener.Addr().(*net.TCPAddr).Port)
			address := "nps_workshop_settings_" + kind + ".test"
			config := func(secret string) string { return settingsSecretsConfig(endpoint, kind, secret) }
			checkStored := func(secret string) resource.TestCheckFunc {
				return func(_ *terraform.State) error {
					api.mu.Lock()
					defer api.mu.Unlock()
					values := []string{}
					switch kind {
					case "chat":
						values = []string{api.chat.GetToken(), api.chat.GetHmacSigningSecret()}
					case "risk_engine":
						values = []string{api.risk.GetLocalPlugins().GetVirusTotal().GetApiKey(), api.risk.GetLocalPlugins().GetReversingLabs().GetPassword()}
						for _, plugin := range api.risk.GetRemotePlugins() {
							values = append(values, plugin.GetSecret(), plugin.GetHeaders()[0].GetValue())
						}
					case "webhooks":
						for _, basic := range []*apipb.WebhookBasicConfig{api.webhooks.GetAuditEvents().GetBasic(), api.webhooks.GetSignalReports().GetBasic(), api.webhooks.GetSoftwareApprovals().GetBasic()} {
							values = append(values, basic.GetHeaders()[0].GetValue())
						}
					}
					for _, got := range values {
						if got != secret {
							return fmt.Errorf("%s secret update: got %q, want %q", kind, got, secret)
						}
					}
					return nil
				}
			}
			steps := []resource.TestStep{{Config: config("original-secret"), Check: checkStored("original-secret")}}
			for _, secret := range []string{"changed-secret", "gcp://project/secret", "aws://secret"} {
				steps = append(steps,
					resource.TestStep{Config: config(secret), Check: checkStored(secret), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}},
				)
			}
			resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: steps})
		})
	}
}

func settingsSecretsConfig(endpoint, kind, secret string) string {
	provider := fmt.Sprintf("provider \"nps\" {\n endpoint = %q\n api_key = \"test-key\"\n}\n", endpoint)
	var body string
	switch kind {
	case "chat":
		body = fmt.Sprintf(`slack = {
 token = %[1]q
 hmac_signing_secret = %[1]q
}`, secret)
	case "risk_engine":
		body = fmt.Sprintf(`local_plugins = {
 virus_total = { api_key = %[1]q }
 reversing_labs = { password = %[1]q }
}
remote_plugins = [{
 name = "plugin"
 uuid = "00000000-0000-4000-8000-000000000001"
 version = "1"
 url = "https://example.invalid/plugin"
 ttl = "5s"
 secret = %[1]q
 headers = [{ key = "Authorization", value = %[1]q }]
}]`, secret)
	case "webhooks":
		for _, name := range []string{"audit_events", "signal_reports", "software_approvals"} {
			body += fmt.Sprintf("%s = {\n headers = [{ key = \"Authorization\", value = %q }]\n}\n", name, secret)
		}
	}
	return provider + fmt.Sprintf("resource \"nps_workshop_settings_%s\" \"test\" {\n%s\n}\n", kind, body)
}

func TestSettingsSecretsUseAPIReferences(t *testing.T) {
	ctx := t.Context()
	chatPrior, diags := chatProtoToModel(ctx, apipb.SlackBotSettings_builder{
		Token: proto.String("old-token"), HmacSigningSecret: proto.String("old-signing-secret"),
	}.Build(), ChatSettingsResourceModel{})
	if diags.HasError() {
		t.Fatal(diags)
	}
	riskSettings := func(secret string) *apipb.RiskEngineSettings {
		return apipb.RiskEngineSettings_builder{
			LocalPlugins: apipb.LocalPluginSettings_builder{
				VirusTotal:    apipb.VirusTotalPluginSettings_builder{ApiKey: proto.String(secret)}.Build(),
				ReversingLabs: apipb.ReversingLabsPluginSettings_builder{Password: proto.String(secret)}.Build(),
			}.Build(),
			RemotePlugins: []*apipb.RemoteRiskEnginePluginSettings{
				apipb.RemoteRiskEnginePluginSettings_builder{Uuid: proto.String("plugin-a"), Secret: proto.String(secret), Headers: []*apipb.HTTPHeader{apipb.HTTPHeader_builder{Key: "Authorization", Value: secret}.Build()}}.Build(),
			},
		}.Build()
	}
	riskPrior, diags := riskEngineProtoToModel(ctx, riskSettings("old-secret"), RiskEngineSettingsResourceModel{})
	if diags.HasError() {
		t.Fatal(diags)
	}
	webhookSettings := func(secret string) *apipb.WebhookSettings {
		return apipb.WebhookSettings_builder{SoftwareApprovals: apipb.WebhookSoftwareApprovalConfig_builder{Basic: apipb.WebhookBasicConfig_builder{
			Headers: []*apipb.HTTPHeader{apipb.HTTPHeader_builder{Key: "Authorization", Value: secret}.Build()},
		}.Build()}.Build()}.Build()
	}
	webhookPrior, diags := webhookProtoToModel(ctx, webhookSettings("old-secret"), WebhookSettingsResourceModel{})
	if diags.HasError() {
		t.Fatal(diags)
	}
	for _, reference := range []string{"gcp://project/secret", "aws://secret"} {
		t.Run(reference, func(t *testing.T) {
			chat, diags := chatProtoToModel(ctx, apipb.SlackBotSettings_builder{Token: proto.String(reference), HmacSigningSecret: proto.String(reference)}.Build(), chatPrior)
			if diags.HasError() {
				t.Fatal(diags)
			}
			chatAPI, diags := chatSlackFromObject(ctx, chat.Slack)
			if diags.HasError() {
				t.Fatal(diags)
			}
			risk, diags := riskEngineProtoToModel(ctx, riskSettings(reference), riskPrior)
			if diags.HasError() {
				t.Fatal(diags)
			}
			riskAPI, diags := riskEngineModelToProto(ctx, &risk)
			if diags.HasError() {
				t.Fatal(diags)
			}
			webhook, diags := webhookProtoToModel(ctx, webhookSettings(reference), webhookPrior)
			if diags.HasError() {
				t.Fatal(diags)
			}
			webhookAPI, diags := webhookSettingsToProto(ctx, webhook)
			if diags.HasError() {
				t.Fatal(diags)
			}
			values := map[string]string{
				"Slack token":            chatAPI.GetToken(),
				"Slack signing secret":   chatAPI.GetHmacSigningSecret(),
				"VirusTotal API key":     riskAPI.GetLocalPlugins().GetVirusTotal().GetApiKey(),
				"ReversingLabs password": riskAPI.GetLocalPlugins().GetReversingLabs().GetPassword(),
				"remote plugin secret":   riskAPI.GetRemotePlugins()[0].GetSecret(),
				"remote plugin header":   riskAPI.GetRemotePlugins()[0].GetHeaders()[0].GetValue(),
				"webhook header":         webhookAPI.GetSoftwareApprovals().GetBasic().GetHeaders()[0].GetValue(),
			}
			for name, got := range values {
				if got != reference {
					t.Errorf("%s: API reference must replace prior secret: got %q, want %q", name, got, reference)
				}
			}
		})
	}
}

func TestSettingsSecretsMatchPluginUUIDsAndHeaderKeys(t *testing.T) {
	ctx := t.Context()
	header := func(key, value string) *apipb.HTTPHeader {
		return apipb.HTTPHeader_builder{Key: key, Value: value}.Build()
	}
	plugin := func(id, secret string, headers ...*apipb.HTTPHeader) *apipb.RemoteRiskEnginePluginSettings {
		return apipb.RemoteRiskEnginePluginSettings_builder{Uuid: proto.String(id), Secret: proto.String(secret), Headers: headers}.Build()
	}
	prior, diags := riskEngineProtoToModel(ctx, apipb.RiskEngineSettings_builder{RemotePlugins: []*apipb.RemoteRiskEnginePluginSettings{
		plugin("a", "secret-a", header("Authorization", "auth-a"), header("X-Token", "token-a")),
		plugin("b", "secret-b", header("Authorization", "auth-b")),
	}}.Build(), RiskEngineSettingsResourceModel{})
	if diags.HasError() {
		t.Fatal(diags)
	}
	got, diags := riskEngineProtoToModel(ctx, apipb.RiskEngineSettings_builder{RemotePlugins: []*apipb.RemoteRiskEnginePluginSettings{
		plugin("b", "", header("authorization", "")),
		plugin("a", "", header("x-token", ""), header("AUTHORIZATION", ""), header("X-New", "")),
		plugin("new", "", header("Authorization", "")),
	}}.Build(), prior)
	if diags.HasError() {
		t.Fatal(diags)
	}
	api, diags := riskEngineModelToProto(ctx, &got)
	if diags.HasError() {
		t.Fatal(diags)
	}
	plugins := api.GetRemotePlugins()
	values := []struct{ name, got, want string }{
		{"reordered plugin b", plugins[0].GetSecret(), "secret-b"},
		{"plugin b header", plugins[0].GetHeaders()[0].GetValue(), "auth-b"},
		{"reordered plugin a", plugins[1].GetSecret(), "secret-a"},
		{"reordered mixed-case token header", plugins[1].GetHeaders()[0].GetValue(), "token-a"},
		{"mixed-case authorization header", plugins[1].GetHeaders()[1].GetValue(), "auth-a"},
		{"new header", plugins[1].GetHeaders()[2].GetValue(), ""},
		{"new plugin secret", plugins[2].GetSecret(), ""},
		{"new plugin header", plugins[2].GetHeaders()[0].GetValue(), ""},
	}
	for _, value := range values {
		if value.got != value.want {
			t.Errorf("%s: got %q, want %q", value.name, value.got, value.want)
		}
	}

	unknownAttributes := prior.RemotePlugins.Elements()[0].(types.Object).Attributes()
	unknownAttributes["uuid"] = types.StringUnknown()
	appliedPlan := prior
	appliedPlan.RemotePlugins = types.ListValueMust(riskRemotePluginObjectType, []attr.Value{types.ObjectValueMust(riskRemotePluginAttrTypes, unknownAttributes)})
	assigned, diags := riskEngineProtoToModel(ctx, apipb.RiskEngineSettings_builder{RemotePlugins: []*apipb.RemoteRiskEnginePluginSettings{
		plugin("assigned-id", "", header("Authorization", ""), header("X-Token", "")),
	}}.Build(), appliedPlan)
	if diags.HasError() {
		t.Fatal(diags)
	}
	assignedAPI, diags := riskEngineModelToProto(ctx, &assigned)
	if diags.HasError() {
		t.Fatal(diags)
	}
	assignedPlugin := assignedAPI.GetRemotePlugins()[0]
	if assignedPlugin.GetUuid() != "assigned-id" || assignedPlugin.GetSecret() != "secret-a" || assignedPlugin.GetHeaders()[0].GetValue() != "auth-a" || assignedPlugin.GetHeaders()[1].GetValue() != "token-a" {
		t.Errorf("new plugin keeps applied secrets after UUID assignment: got %v", assignedPlugin)
	}
	webhookSettings := func(headers ...*apipb.HTTPHeader) *apipb.WebhookSettings {
		return apipb.WebhookSettings_builder{SoftwareApprovals: apipb.WebhookSoftwareApprovalConfig_builder{Basic: apipb.WebhookBasicConfig_builder{Headers: headers}.Build()}.Build()}.Build()
	}
	webhookPrior, diags := webhookProtoToModel(ctx, webhookSettings(header("Authorization", "auth"), header("X-Token", "token")), WebhookSettingsResourceModel{})
	if diags.HasError() {
		t.Fatal(diags)
	}
	webhook, diags := webhookProtoToModel(ctx, webhookSettings(header("x-token", ""), header("AUTHORIZATION", ""), header("X-New", "")), webhookPrior)
	if diags.HasError() {
		t.Fatal(diags)
	}
	webhookAPI, diags := webhookSettingsToProto(ctx, webhook)
	if diags.HasError() {
		t.Fatal(diags)
	}
	for i, want := range []string{"token", "auth", ""} {
		if got := webhookAPI.GetSoftwareApprovals().GetBasic().GetHeaders()[i].GetValue(); got != want {
			t.Errorf("webhook header %d: got %q, want %q", i, got, want)
		}
	}
}
