package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/mockoidc"

	"github.com/brunoxpera/risksignal/internal/adapters/oidc"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// startMock starts the roles-claim mock provider on a loopback listener and
// returns it (torn down with the test).
func startMock(t *testing.T, cfg mockConfig) *mockoidc.MockOIDC {
	t.Helper()
	m, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := m.Start(ln, nil); err != nil {
		t.Fatalf("start mock: %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })
	return m
}

// newVerifier builds the RiskSignal adapter over the running mock.
func newVerifier(t *testing.T, m *mockoidc.MockOIDC) *oidc.Verifier {
	t.Helper()
	v, err := oidc.New(oidc.Config{
		Issuer:       m.Issuer(),
		ClientID:     m.ClientID,
		ClientSecret: m.ClientSecret,
		RedirectURL:  "https://app.local/callback",
		RoleMappings: map[string]domain.Role{
			"analysts": domain.RoleSecurityAnalyst,
			"admins":   domain.RoleAdministrator,
		},
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return v
}

// authorize runs the authorization request against the mock (simulating the
// browser) without following the redirect, and returns the code, state and the
// originating AuthRequest.
func authorize(t *testing.T, v *oidc.Verifier) (code, state string, req oidc.AuthRequest) {
	t.Helper()
	req, err := v.NewAuthRequest("https://app.local/callback")
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	authURL, err := v.AuthorizationURL(context.Background(), req)
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize Location: %v", err)
	}
	return loc.Query().Get("code"), loc.Query().Get("state"), req
}

// TestMockOIDCLoginRoundTrip proves the extended mock emits the roles claim and
// that the adapter's Code+PKCE exchange verifies the issued id token and maps
// the identity and roles end to end.
func TestMockOIDCLoginRoundTrip(t *testing.T) {
	m := startMock(t, mockConfig{
		Subject: "user-42",
		Email:   "ada@example.com",
		Name:    "ada",
		Roles:   []string{"analysts", "admins", "unmapped-value"},
	})
	v := newVerifier(t, m)

	code, state, req := authorize(t, v)
	ident, err := v.Exchange(context.Background(), code, state, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if want := m.Issuer() + "::user-42"; ident.SubjectID != want {
		t.Errorf("SubjectID = %q, want %q", ident.SubjectID, want)
	}
	if ident.DisplayName != "ada" {
		t.Errorf("DisplayName = %q, want ada", ident.DisplayName)
	}
	if ident.Email != "ada@example.com" {
		t.Errorf("Email = %q, want ada@example.com", ident.Email)
	}
	want := []domain.Role{domain.RoleSecurityAnalyst, domain.RoleAdministrator}
	if len(ident.Roles) != len(want) {
		t.Fatalf("Roles = %v, want %v", ident.Roles, want)
	}
	for i := range want {
		if ident.Roles[i] != want[i] {
			t.Fatalf("Roles = %v, want %v", ident.Roles, want)
		}
	}
}

// TestMockOIDCAccessTokenVerifiesWithoutRoles proves the access token verifies
// too, and — carrying no roles claim — maps to zero roles (fail closed).
func TestMockOIDCAccessTokenVerifiesWithoutRoles(t *testing.T) {
	m := startMock(t, mockConfig{
		Subject: "user-42",
		Email:   "ada@example.com",
		Name:    "ada",
		Roles:   []string{"analysts"},
	})
	v := newVerifier(t, m)

	code, _, req := authorize(t, v)
	resp, err := http.PostForm(m.TokenEndpoint(), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {req.RedirectURL},
		"code_verifier": {req.CodeVerifier},
		"client_id":     {m.ClientID},
		"client_secret": {m.ClientSecret},
	})
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("token response carried no access token")
	}

	ident, err := v.Verify(context.Background(), tr.AccessToken)
	if err != nil {
		t.Fatalf("Verify(access token): %v", err)
	}
	if want := m.Issuer() + "::user-42"; ident.SubjectID != want {
		t.Errorf("SubjectID = %q, want %q", ident.SubjectID, want)
	}
	if len(ident.Roles) != 0 {
		t.Errorf("Roles = %v, want none (the access token carries no roles claim)", ident.Roles)
	}
}
