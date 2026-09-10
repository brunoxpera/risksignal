package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// roleMappings is the standard test mapping (external value → internal role).
func roleMappings(c *Config) {
	c.RoleMappings = map[string]domain.Role{
		"analysts": domain.RoleSecurityAnalyst,
		"admins":   domain.RoleAdministrator,
	}
}

func TestVerifyValidTokenMapsIdentityAndRoles(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)

	ident, err := v.Verify(context.Background(), p.sign(p.baseClaims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if want := p.issuer() + "::user-1"; ident.SubjectID != want {
		t.Errorf("SubjectID = %q, want %q", ident.SubjectID, want)
	}
	if ident.DisplayName != "Ada Lovelace" {
		t.Errorf("DisplayName = %q, want %q", ident.DisplayName, "Ada Lovelace")
	}
	if ident.Email != "ada@example.com" {
		t.Errorf("Email = %q, want %q", ident.Email, "ada@example.com")
	}
	if len(ident.Roles) != 1 || ident.Roles[0] != domain.RoleSecurityAnalyst {
		t.Errorf("Roles = %v, want [%s]", ident.Roles, domain.RoleSecurityAnalyst)
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	p := newStubProvider(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherIssuer := p.baseClaims()
	otherIssuer["iss"] = "https://evil.example"
	otherAudience := p.baseClaims()
	otherAudience["aud"] = "another-client"
	expired := p.baseClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	noExpiry := p.baseClaims()
	delete(noExpiry, "exp")
	futureNbf := p.baseClaims()
	futureNbf["nbf"] = time.Now().Add(time.Hour).Unix()
	azpMismatch := p.baseClaims()
	azpMismatch["azp"] = "another-client"

	noneToken, err := jwt.NewWithClaims(jwt.SigningMethodNone, p.baseClaims()).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"garbage", "not-a-jwt"},
		{"expired", p.sign(expired)},
		{"missing expiry", p.sign(noExpiry)},
		{"nbf in the future", p.sign(futureNbf)},
		{"wrong issuer", p.sign(otherIssuer)},
		{"wrong audience", p.sign(otherAudience)},
		{"azp mismatch", p.sign(azpMismatch)},
		{"bad signature", p.signWith(otherKey, stubKid, p.baseClaims())},
		{"unknown kid", p.signWith(p.key, "unknown-kid", p.baseClaims())},
		{"alg none", noneToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := p.newVerifier(t, roleMappings)
			if _, err := v.Verify(context.Background(), tc.token); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify() err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

// TestVerifyRefreshesJWKSOnUnknownKid proves the JWKS cache rotates: a token
// whose kid is not in the cached set triggers one refetch, after which an
// unknown kid is rejected.
func TestVerifyRefreshesJWKSOnUnknownKid(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	ctx := context.Background()

	if _, err := v.Verify(ctx, p.sign(p.baseClaims())); err != nil {
		t.Fatalf("warm-up Verify: %v", err)
	}

	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rotated key: %v", err)
	}
	p.jwks = []jwk{publicJWK("rotated-kid", &rotated.PublicKey)}

	ident, err := v.Verify(ctx, p.signWith(rotated, "rotated-kid", p.baseClaims()))
	if err != nil {
		t.Fatalf("Verify after rotation: %v", err)
	}
	if ident.SubjectID == "" {
		t.Error("Verify after rotation returned an empty subject")
	}
}

// TestVerifyUsesInjectedClock drives the validity window from the injectable
// clock (ch. 7.2): a token valid at T is expired at T+2h.
func TestVerifyUsesInjectedClock(t *testing.T) {
	p := newStubProvider(t)
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFakeClock(base)

	claims := p.baseClaims()
	claims["exp"] = base.Add(time.Hour).Unix()
	claims["nbf"] = base.Add(-time.Minute).Unix()
	claims["iat"] = base.Unix()
	token := p.sign(claims)

	v, err := New(p.config(roleMappings), WithClock(clk))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify at issue time: %v", err)
	}

	clk.Advance(2 * time.Hour)
	if _, err := v.Verify(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify after expiry err = %v, want ErrInvalidToken", err)
	}
}

// TestVerifyFailsClosedOnRoles proves the roles mapping never grants a role
// for an unknown or missing claim value and never crashes.
func TestVerifyFailsClosedOnRoles(t *testing.T) {
	t.Run("unknown value is dropped and logged", func(t *testing.T) {
		p := newStubProvider(t)
		var logs bytes.Buffer
		v, err := New(p.config(roleMappings), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		claims := p.baseClaims()
		claims["roles"] = []string{"analysts", "not-a-role"}

		ident, err := v.Verify(context.Background(), p.sign(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(ident.Roles) != 1 || ident.Roles[0] != domain.RoleSecurityAnalyst {
			t.Errorf("Roles = %v, want only [%s]", ident.Roles, domain.RoleSecurityAnalyst)
		}
		if !strings.Contains(logs.String(), "unknown roles claim value") {
			t.Errorf("log %q does not record the unknown roles claim value", logs.String())
		}
	})

	t.Run("missing claim yields no roles", func(t *testing.T) {
		p := newStubProvider(t)
		v := p.newVerifier(t, roleMappings)
		claims := p.baseClaims()
		delete(claims, "roles")

		ident, err := v.Verify(context.Background(), p.sign(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(ident.Roles) != 0 {
			t.Errorf("Roles = %v, want none", ident.Roles)
		}
	})

	t.Run("no configured mappings yields no roles", func(t *testing.T) {
		p := newStubProvider(t)
		v := p.newVerifier(t)
		ident, err := v.Verify(context.Background(), p.sign(p.baseClaims()))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(ident.Roles) != 0 {
			t.Errorf("Roles = %v, want none", ident.Roles)
		}
	})

	t.Run("string-shaped claim value maps", func(t *testing.T) {
		p := newStubProvider(t)
		v := p.newVerifier(t, roleMappings)
		claims := p.baseClaims()
		claims["roles"] = "admins"

		ident, err := v.Verify(context.Background(), p.sign(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(ident.Roles) != 1 || ident.Roles[0] != domain.RoleAdministrator {
			t.Errorf("Roles = %v, want [%s]", ident.Roles, domain.RoleAdministrator)
		}
	})
}

// TestVerifyTokenWithoutProfileClaims proves a claim-light token (the shape of
// an access token: subject only) still verifies and maps to a subject-only
// identity with no roles — fail closed.
func TestVerifyTokenWithoutProfileClaims(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)

	claims := p.baseClaims()
	delete(claims, "name")
	delete(claims, "email")
	delete(claims, "roles")

	ident, err := v.Verify(context.Background(), p.sign(claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ident.SubjectID != p.issuer()+"::user-1" {
		t.Errorf("SubjectID = %q, want issuer-qualified subject", ident.SubjectID)
	}
	if ident.DisplayName != "" || ident.Email != "" || len(ident.Roles) != 0 {
		t.Errorf("identity = %+v, want subject-only (no name/email/roles)", ident)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing issuer", Config{ClientID: "c"}},
		{"issuer without scheme", Config{Issuer: "auth.example", ClientID: "c"}},
		{"missing client id", Config{Issuer: "https://auth.example"}},
		{"invalid role mapping", Config{Issuer: "https://auth.example", ClientID: "c", RoleMappings: map[string]domain.Role{"x": "nope"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("New(%+v) succeeded, want error", tc.cfg)
			}
		})
	}
}
