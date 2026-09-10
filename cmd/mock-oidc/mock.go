// mock-oidc roles-claim extension (WP-5a.04, ARCH-005 §2, D-003). The stock
// mockoidc provider issues id tokens without a roles claim; RiskSignal's
// first-login role seeding reads one. This file wraps the mock provider so the
// configured test user always emits a `roles` array claim (and the matching
// userinfo member), so the login and role-matrix tests are self-contained.
//
// The user is configurable through the environment, so one sidecar serves the
// role matrix by restart:
//
//	MOCK_OIDC_SUBJECT (default "1234567890")
//	MOCK_OIDC_EMAIL   (default "jane.doe@example.com")
//	MOCK_OIDC_NAME    (default "jane.doe")
//	MOCK_OIDC_ROLES   (default "security_analyst"; comma/space separated)
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
)

// Environment keys of the mock user. The mock-oidc sidecar is a standalone
// test tool, so it uses its own MOCK_OIDC_* namespace rather than the
// RISKSIGNAL_* product configuration.
const (
	envSubject = "MOCK_OIDC_SUBJECT"
	envEmail   = "MOCK_OIDC_EMAIL"
	envName    = "MOCK_OIDC_NAME"
	envRoles   = "MOCK_OIDC_ROLES"

	defaultSubject = "1234567890"
	defaultEmail   = "jane.doe@example.com"
	defaultName    = "jane.doe"
	defaultRoles   = "security_analyst"
)

// mockConfig is the mock user the sidecar issues tokens for.
type mockConfig struct {
	Subject string
	Email   string
	Name    string
	Roles   []string
}

// user builds the mockoidc.User of the configuration.
func (c mockConfig) user() mockoidc.User {
	return &rolesUser{
		MockUser: &mockoidc.MockUser{
			Subject:           c.Subject,
			Email:             c.Email,
			EmailVerified:     true,
			PreferredUsername: c.Name,
		},
		roles: c.Roles,
	}
}

// mockConfigFromEnv reads the mock user from the environment, falling back to
// the documented defaults.
func mockConfigFromEnv() mockConfig {
	return mockConfig{
		Subject: envOr(envSubject, defaultSubject),
		Email:   envOr(envEmail, defaultEmail),
		Name:    envOr(envName, defaultName),
		Roles:   splitList(envOr(envRoles, defaultRoles)),
	}
}

// newServer builds the mock provider with the roles-claim middleware. Every
// authorization request pops the configured user (with its roles claim) off
// the queue instead of mockoidc's role-less DefaultUser.
func newServer(cfg mockConfig) (*mockoidc.MockOIDC, error) {
	m, err := mockoidc.NewServer(nil)
	if err != nil {
		return nil, fmt.Errorf("create mock OIDC server: %w", err)
	}
	err = m.AddMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == mockoidc.AuthorizationEndpoint {
				m.QueueUser(cfg.user())
			}
			next.ServeHTTP(w, r)
		})
	})
	if err != nil {
		return nil, fmt.Errorf("add roles middleware: %w", err)
	}
	return m, nil
}

// rolesUser is a mockoidc.User that adds a `roles` claim to the id token and a
// `roles` member to the userinfo response. The remaining claims are exactly
// mockoidc's (email, preferred_username, …), so only the roles addition is
// tested.
type rolesUser struct {
	*mockoidc.MockUser
	roles []string
}

// Claims returns the id-token claims: the mock user's claims plus the roles
// array.
func (u *rolesUser) Claims(scope []string, base *mockoidc.IDTokenClaims) (jwt.Claims, error) {
	inner, err := u.MockUser.Claims(scope, base)
	if err != nil {
		return nil, err
	}
	claims, err := toMapClaims(inner)
	if err != nil {
		return nil, err
	}
	if len(u.roles) > 0 {
		claims["roles"] = u.roles
	}
	return claims, nil
}

// Userinfo returns the mock user's userinfo plus the roles array.
func (u *rolesUser) Userinfo(scope []string) ([]byte, error) {
	inner, err := u.MockUser.Userinfo(scope)
	if err != nil {
		return nil, err
	}
	info, err := toMapClaims(inner)
	if err != nil {
		return nil, err
	}
	if len(u.roles) > 0 {
		info["roles"] = u.roles
	}
	return json.Marshal(info)
}

// toMapClaims normalises a claims value (a mockoidc struct or raw JSON bytes)
// into a jwt.MapClaims so the roles member can be added.
func toMapClaims(v any) (jwt.MapClaims, error) {
	raw, ok := v.([]byte)
	if !ok {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	claims := jwt.MapClaims{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// envOr returns the trimmed environment value or the fallback when unset or
// empty.
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// splitList splits a comma- or whitespace-separated list, dropping empties.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
