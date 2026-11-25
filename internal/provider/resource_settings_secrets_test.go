// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type settingsSecretServer struct {
	svcpb.UnimplementedWorkshopServiceServer
	mu            sync.Mutex
	returnSecrets bool
	assignUUIDs   bool
	uuids         int
	chat          *apipb.SlackBotSettings
	risk          *apipb.RiskEngineSettings
	webhooks      *apipb.WebhookSettings
}

// The clear-on-read server keeps stored header values on an empty write.
func keepHeaders(in, stored []*apipb.HTTPHeader) {
	for _, h := range in {
		for _, s := range stored {
			if h.GetValue() == "" && strings.EqualFold(h.GetKey(), s.GetKey()) {
				h.SetValue(s.GetValue())
			}
		}
	}
}

func (s *settingsSecretServer) read(value string) string {
	if s.returnSecrets {
		return value
	}
	return ""
}

func (s *settingsSecretServer) readHeaders(headers []*apipb.HTTPHeader) {
	for _, h := range headers {
		h.SetValue(s.read(h.GetValue()))
	}
}

func (s *settingsSecretServer) fillUUIDs() {
	for _, p := range s.risk.GetRemotePlugins() {
		if p.GetUuid() == "" {
			s.uuids++
			p.SetUuid(fmt.Sprintf("uuid-%d", s.uuids))
		}
	}
}

func (s *settingsSecretServer) GetChatSettings(context.Context, *apipb.GetChatSettingsRequest) (*apipb.GetChatSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var chat *apipb.SlackBotSettings
	if s.chat != nil {
		chat = proto.Clone(s.chat).(*apipb.SlackBotSettings)
		chat.SetToken(s.read(chat.GetToken()))
		chat.SetHmacSigningSecret(s.read(chat.GetHmacSigningSecret()))
	}
	return apipb.GetChatSettingsResponse_builder{SlackBotSettings: chat}.Build(), nil
}

func (s *settingsSecretServer) UpdateChatSettings(_ context.Context, req *apipb.UpdateChatSettingsRequest) (*apipb.UpdateChatSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := proto.Clone(req.GetSlackBotSettings()).(*apipb.SlackBotSettings)
	s.chat = in
	return apipb.UpdateChatSettingsResponse_builder{}.Build(), nil
}

func (s *settingsSecretServer) GetRiskEngineSettings(context.Context, *apipb.GetRiskEngineSettingsRequest) (*apipb.GetRiskEngineSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var risk *apipb.RiskEngineSettings
	if s.risk != nil {
		risk = proto.Clone(s.risk).(*apipb.RiskEngineSettings)
		if vt := risk.GetLocalPlugins().GetVirusTotal(); vt != nil {
			vt.SetApiKey(s.read(vt.GetApiKey()))
		}
		if rl := risk.GetLocalPlugins().GetReversingLabs(); rl != nil {
			rl.SetPassword(s.read(rl.GetPassword()))
		}
		for _, p := range risk.GetRemotePlugins() {
			p.SetSecret(s.read(p.GetSecret()))
			s.readHeaders(p.GetHeaders())
		}
	}
	return apipb.GetRiskEngineSettingsResponse_builder{RiskEngineSettings: risk}.Build(), nil
}

func (s *settingsSecretServer) UpdateRiskEngineSettings(_ context.Context, req *apipb.UpdateRiskEngineSettingsRequest) (*apipb.UpdateRiskEngineSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := proto.Clone(req.GetRiskEngineSettings()).(*apipb.RiskEngineSettings)
	s.risk = in
	if s.assignUUIDs {
		s.fillUUIDs()
	}
	return apipb.UpdateRiskEngineSettingsResponse_builder{}.Build(), nil
}

func webhookBasics(w *apipb.WebhookSettings) []*apipb.WebhookBasicConfig {
	return []*apipb.WebhookBasicConfig{w.GetAuditEvents().GetBasic(), w.GetSignalReports().GetBasic(), w.GetSoftwareApprovals().GetBasic()}
}

func (s *settingsSecretServer) GetWebhookSettings(context.Context, *apipb.GetWebhookSettingsRequest) (*apipb.GetWebhookSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var settings *apipb.WebhookSettings
	if s.webhooks != nil {
		settings = proto.Clone(s.webhooks).(*apipb.WebhookSettings)
		for _, basic := range webhookBasics(settings) {
			if basic != nil {
				basic.SetSecret("")
				s.readHeaders(basic.GetHeaders())
			}
		}
	}
	return apipb.GetWebhookSettingsResponse_builder{Settings: settings}.Build(), nil
}

func (s *settingsSecretServer) UpdateWebhookSettings(_ context.Context, req *apipb.UpdateWebhookSettingsRequest) (*apipb.UpdateWebhookSettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := proto.Clone(req.GetSettings()).(*apipb.WebhookSettings)
	if !s.returnSecrets {
		stored := webhookBasics(s.webhooks)
		for i, basic := range webhookBasics(in) {
			if basic != nil {
				keepHeaders(basic.GetHeaders(), stored[i].GetHeaders())
			}
		}
	}
	s.webhooks = in
	return apipb.UpdateWebhookSettingsResponse_builder{}.Build(), nil
}

func (s *settingsSecretServer) storedSecrets(kind string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kind {
	case "chat":
		return []string{s.chat.GetToken(), s.chat.GetHmacSigningSecret()}
	case "risk_engine":
		values := []string{s.risk.GetLocalPlugins().GetVirusTotal().GetApiKey(), s.risk.GetLocalPlugins().GetReversingLabs().GetPassword()}
		for _, p := range s.risk.GetRemotePlugins() {
			values = append(values, p.GetSecret(), p.GetHeaders()[0].GetValue())
		}
		return values
	default:
		var values []string
		for _, basic := range webhookBasics(s.webhooks) {
			values = append(values, basic.GetHeaders()[0].GetValue())
		}
		return values
	}
}

func startSettingsSecretServer(t *testing.T, api *settingsSecretServer) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	svcpb.RegisterWorkshopServiceServer(server, api)
	t.Cleanup(server.Stop)
	go func() { _ = server.Serve(listener) }()
	return fmt.Sprintf("localhost:%d", listener.Addr().(*net.TCPAddr).Port)
}

func expectStored(api *settingsSecretServer, kind, want string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		for _, got := range api.storedSecrets(kind) {
			if got != want {
				return fmt.Errorf("%s: API holds secret %q, want %q", kind, got, want)
			}
		}
		return nil
	}
}

var plainSecretPaths = map[string][]string{
	"chat":        {"slack.token", "slack.hmac_signing_secret"},
	"risk_engine": {"local_plugins.virus_total.api_key", "local_plugins.reversing_labs.password", "remote_plugins.0.secret", "remote_plugins.0.headers.0.value"},
	"webhooks":    {"audit_events.headers.0.value", "signal_reports.headers.0.value", "software_approvals.headers.0.value"},
}

func TestSettingsSecretsPlan(t *testing.T) {
	t.Setenv("WORKSHOP_API_KEY", "")
	for _, returnSecrets := range []bool{false, true} {
		for _, kind := range []string{"chat", "risk_engine", "webhooks"} {
			t.Run(fmt.Sprintf("%s/returnSecrets=%t", kind, returnSecrets), func(t *testing.T) {
				api := &settingsSecretServer{returnSecrets: returnSecrets, assignUUIDs: true}
				endpoint := startSettingsSecretServer(t, api)
				address := "nps_workshop_settings_" + kind + ".test"
				update := resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}
				var noPlainSecrets []resource.TestCheckFunc
				for _, p := range plainSecretPaths[kind] {
					noPlainSecrets = append(noPlainSecrets, resource.TestCheckNoResourceAttr(address, p))
				}
				woStep := func(secret, version string, plan resource.ConfigPlanChecks, stored string) resource.TestStep {
					return resource.TestStep{
						Config:           settingsSecretsConfig(endpoint, kind, secret, version),
						ConfigPlanChecks: plan,
						Check:            resource.ComposeTestCheckFunc(append(slices.Clone(noPlainSecrets), expectStored(api, kind, stored))...),
					}
				}
				steps := []resource.TestStep{
					{Config: settingsSecretsConfig(endpoint, kind, "plain-1", ""), Check: expectStored(api, kind, "plain-1")},
					{Config: settingsSecretsConfig(endpoint, kind, "plain-2", ""), ConfigPlanChecks: update, Check: expectStored(api, kind, "plain-2")},
					woStep("wo-1", "1", update, "wo-1"),
					woStep("wo-2", "1", resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}, "wo-1"),
					woStep("wo-2", "2", update, "wo-2"),
				}
				if kind == "risk_engine" {
					steps[0].Check = resource.ComposeTestCheckFunc(steps[0].Check, resource.TestCheckResourceAttr(address, "remote_plugins.0.uuid", "uuid-1"))
				}
				testCase := resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: steps}
				if kind == "webhooks" {
					testCase.CheckDestroy = func(state *terraform.State) error {
						api.mu.Lock()
						defer api.mu.Unlock()
						for _, basic := range webhookBasics(api.webhooks) {
							if basic.GetEnabled() {
								return fmt.Errorf("webhook still enabled after destroy")
							}
							if got := basic.GetHeaders()[0].GetValue(); got != "wo-2" {
								return fmt.Errorf("header value after destroy: got %q, want \"wo-2\"", got)
							}
						}
						return nil
					}
				}
				resource.UnitTest(t, testCase)
			})
		}
	}
}

func TestSettingsSecretsPluginWithoutUUID(t *testing.T) {
	t.Setenv("WORKSHOP_API_KEY", "")
	for _, returnSecrets := range []bool{false, true} {
		t.Run(fmt.Sprintf("returnSecrets=%t", returnSecrets), func(t *testing.T) {
			api := &settingsSecretServer{returnSecrets: returnSecrets}
			endpoint := startSettingsSecretServer(t, api)
			address := "nps_workshop_settings_risk_engine.test"
			config := settingsSecretsConfig(endpoint, "risk_engine", "plain-1", "")
			resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: testAccProtoV6ProviderFactories, Steps: []resource.TestStep{
				{Config: config, Check: resource.TestCheckNoResourceAttr(address, "remote_plugins.0.uuid")},
				{
					PreConfig: func() {
						api.mu.Lock()
						defer api.mu.Unlock()
						api.fillUUIDs()
					},
					Config:           config,
					ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(address, "remote_plugins.0.uuid", "uuid-1"),
						resource.TestCheckResourceAttr(address, "remote_plugins.0.secret", "plain-1"),
					),
				},
			}})
		})
	}
}

func settingsSecretsConfig(endpoint, kind, secret, version string) string {
	provider := fmt.Sprintf("provider \"nps\" {\n endpoint = %q\n api_key = \"test-key\"\n}\n", endpoint)
	attr := func(name string) string {
		if version != "" {
			return fmt.Sprintf("%s_wo = %q", name, secret)
		}
		return fmt.Sprintf("%s = %q", name, secret)
	}
	var body string
	if version != "" && kind != "webhooks" {
		body = fmt.Sprintf("secrets_wo_version = %q\n", version)
	}
	switch kind {
	case "chat":
		body += fmt.Sprintf("slack = {\n %s\n %s\n}\n", attr("token"), attr("hmac_signing_secret"))
	case "risk_engine":
		body += fmt.Sprintf(`local_plugins = {
 virus_total = { %s }
 reversing_labs = { %s }
}
remote_plugins = [{
 name = "plugin"
 version = "1"
 url = "https://example.invalid/plugin"
 ttl = "5s"
 %s
 headers = [{ key = "Authorization", %s }]
}]
`, attr("api_key"), attr("password"), attr("secret"), attr("value"))
	case "webhooks":
		versionLine := ""
		if version != "" {
			versionLine = fmt.Sprintf("secret_wo_version = %q", version)
		}
		for _, name := range []string{"audit_events", "signal_reports", "software_approvals"} {
			body += fmt.Sprintf("%s = {\n enabled = true\n %s\n headers = [{ key = \"Authorization\", %s }]\n}\n", name, versionLine, attr("value"))
		}
	}
	return provider + fmt.Sprintf("resource \"nps_workshop_settings_%s\" \"test\" {\n%s}\n", kind, body)
}
