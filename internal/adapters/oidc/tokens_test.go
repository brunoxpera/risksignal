package oidc

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestDeviceLoginWithTokensReturnsTokenSet proves the login plumbing receives
// the whole token set (the CLI persists it), including the derived expiry,
// while the identity-only DeviceLogin keeps its signature.
func TestDeviceLoginWithTokensReturnsTokenSet(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	v.sleep = func(context.Context, time.Duration) error { return nil }

	p.device = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"device_code": "device-1", "user_code": "U", "interval": 1})
	}
	p.token = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"id_token":      p.sign(p.baseClaims()),
			"access_token":  "at-secret",
			"refresh_token": "rt-secret",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}

	before := time.Now()
	tokens, err := v.DeviceLoginWithTokens(context.Background(), nil)
	if err != nil {
		t.Fatalf("DeviceLoginWithTokens: %v", err)
	}
	if tokens.AccessToken != "at-secret" || tokens.RefreshToken != "rt-secret" ||
		tokens.IDToken == "" || tokens.TokenType != "Bearer" {
		t.Fatalf("tokens = %+v, want the full token set", tokens)
	}
	if tokens.Identity.SubjectID != p.issuer()+"::user-1" {
		t.Fatalf("identity subject = %q, want the issuer-qualified subject", tokens.Identity.SubjectID)
	}
	// The expiry is derived from expires_in against the injected (real) clock.
	if tokens.ExpiresAt.Before(before.Add(59*time.Minute)) || tokens.ExpiresAt.After(before.Add(61*time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want ~1h after the login", tokens.ExpiresAt)
	}
}
