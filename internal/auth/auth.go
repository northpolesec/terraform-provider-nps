package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/credentials"
)

const (
	// Path, relative to the user's home directory, where the token should be stored.
	tokenFilePathSuffix = ".config/tf_nps_token.json"
)

// Used by the login command to retrieve and store a device access token.
func GetAndStoreToken(ctx context.Context, serverURL string) error {
	cfg, _, err := createConfig(ctx, serverURL)
	if err != nil {
		return err
	}

	deviceAuthResp, err := cfg.DeviceAuth(context.Background())
	if err != nil {
		return fmt.Errorf("failed to request device authorization: %v", err)
	}

	browser.OpenURL(deviceAuthResp.VerificationURIComplete)

	fmt.Println("Attempting to automatically open the SSO authorization page in your default browser.")
	fmt.Println("If the browser does not open or you wish to use a different device to authorize this request, open the following URL:")
	fmt.Println()
	fmt.Printf("%s\n", deviceAuthResp.VerificationURIComplete)
	fmt.Println()
	fmt.Println("Waiting for token...")

	// This will block until the user has authorized the request or the device
	// code expires.
	token, err := cfg.DeviceAccessToken(ctx, deviceAuthResp)
	if err != nil {
		return fmt.Errorf("failed to get device access token: %v", err)
	}

	addTokenExpiry(token)

	// Write the token out to the file so it's ready for use in RPC requests.
	if err := writeTokenToFile(token); err != nil {
		return fmt.Errorf("failed to write token to file: %v", err)
	}

	fmt.Println("Successfully logged in")
	return nil
}

// Used by the provider to retrieve a usable credentials.PerRPCCredentials call option.
// The required credentials come from:
//  1. The WORKSHOP_API_KEY environment variable
//  2. The input key from the Terraform provider config
//  3. A valid token stored in the user's home directory
//
// If no valid credentials are found, an error is returned advising the user to run
// the provider binary with the -login flag so that a new device access token can be
// retrieved.
func APIKeyOrToken(ctx context.Context, inputKey, serverURL string) (credentials.PerRPCCredentials, error) {
	// First try to get an API key from the environment.
	if e := os.Getenv("WORKSHOP_API_KEY"); e != "" {
		return apiKeyAuthorizer(e), nil
	}

	// Then check if the Terraform provider config had a key.
	if inputKey != "" {
		return apiKeyAuthorizer(inputKey), nil
	}

	cfg, insecure, err := createConfig(ctx, serverURL)
	if err != nil {
		return nil, err
	}

	// Those failed, let's see if there's a valid token?
	token := apiTokenFromFile(ctx)
	if token != nil {
		tflog.Info(ctx, "Using existing API token from file")
		return oauthRPCCreds{ts: cfg.TokenSource(context.Background(), token), insecure: insecure}, nil
	}

	//lint:ignore ST1005 This error is directly presented to the user without
	// any prefix so we need to capitalize it.
	return nil, fmt.Errorf("Not logged in. Run `%s -login %s` to login", os.Args[0], serverURL)
}

func createConfig(_ context.Context, endpoint string) (*oauth2.Config, bool, error) {
	insecure := false
	if endpoint == "localhost:8080" {
		insecure = true
		endpoint = "http://localhost:8080/.well-known/workos-client-id"
	} else {
		endpoint = fmt.Sprintf("https://%s/.well-known/workos-client-id", endpoint)
	}

	resp, err := http.Get(endpoint)
	if err != nil || resp.StatusCode != 200 {
		return nil, insecure, fmt.Errorf("failed to get client ID from endpoint: %v", err)
	}

	clientID, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, insecure, fmt.Errorf("failed to read response body: %v", err)
	}

	return &oauth2.Config{
		ClientID: string(clientID),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: "https://api.workos.com/user_management/authorize/device",
			TokenURL:      "https://api.workos.com/user_management/authenticate",
		},
	}, insecure, nil
}

func apiTokenFromFile(ctx context.Context) *oauth2.Token {
	usr, _ := user.Current()
	dir := usr.HomeDir
	filePath := filepath.Join(dir, tokenFilePathSuffix)

	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		tflog.Error(ctx, "Failed to read API token from file", map[string]any{"err": err})
		return nil
	}

	var t oauth2.Token
	if err := json.Unmarshal(fileContent, &t); err != nil {
		tflog.Error(ctx, "Failed to unmarshal API token from file", map[string]any{"err": err})
		return nil
	}

	if t.AccessToken == "" && t.RefreshToken == "" {
		tflog.Error(ctx, "API token from file is empty")
		return nil
	}

	return &t
}

func writeTokenToFile(token *oauth2.Token) error {
	usr, _ := user.Current()
	dir := usr.HomeDir
	filePath := filepath.Join(dir, tokenFilePathSuffix)

	b, err := json.Marshal(token)
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, b, 0600)
}

func deleteTokenFromFile() error {
	usr, _ := user.Current()
	dir := usr.HomeDir
	filePath := filepath.Join(dir, tokenFilePathSuffix)
	return os.Remove(filePath)
}

// APIKeyAuthorizer is a PerRPCCredentials implementation that uses a static API key.
type apiKeyAuthorizer string

func (k apiKeyAuthorizer) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"Authorization": string(k)}, nil
}
func (k apiKeyAuthorizer) RequireTransportSecurity() bool {
	return false
}

// oauthRPCCreds is a PerRPCCredentials implementation that uses an OAuth TokenSource.
// The gRPC library already has an implementation of this but it cannot be used with
// insecure connections, which makes localhost testing impossible.
type oauthRPCCreds struct {
	ts       oauth2.TokenSource
	insecure bool
}

func (o oauthRPCCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token, err := o.ts.Token()
	if err != nil {
		if err := deleteTokenFromFile(); err != nil {
			tflog.Error(ctx, "Failed to delete token from file", map[string]any{"err": err})
		}
		return nil, err
	}

	// Add the expiration time to the token if it's not already set.
	addTokenExpiry(token)

	// Write the token to the file.
	writeTokenToFile(token)

	if !o.insecure {
		ri, _ := credentials.RequestInfoFromContext(ctx)
		if err = credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
			return nil, fmt.Errorf("unable to transfer TokenSource PerRPCCredentials: %v", err)
		}
	}

	return map[string]string{
		"authorization": token.Type() + " " + token.AccessToken,
	}, nil
}

func (o oauthRPCCreds) RequireTransportSecurity() bool {
	return !o.insecure
}

// addTokenExpiry adds the expiry time to the token if it's not already set.
// The response from WorkOS doesn't include an expiry time so we have to parse
// the access token JWT ourselves and add the expiry to the "outer" token. This
// enables the oauth2.TokenSource to automatically refresh the token when it
// expires using the refresh token.
func addTokenExpiry(token *oauth2.Token) {
	if !token.Expiry.IsZero() {
		return
	}

	parser := jwt.NewParser()
	parsedToken, _, err := parser.ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return
	}

	exp, err := parsedToken.Claims.GetExpirationTime()
	if err != nil {
		return
	}

	token.Expiry = exp.Time
}
