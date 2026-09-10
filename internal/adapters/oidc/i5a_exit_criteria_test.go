package oidc

// I5a exit-criterion proof (d) — token and claim hardening (ARCH-005 §2, §8(d);
// NFR-014).
//
// The token/claim rejection cases are unit-tested directly against the
// verifier (verifier_test.go TestVerifyRejectsBadTokens, TestVerifyFailsClosed
// OnRoles) and the browser-flow PKCE/state/nonce checks against the code flow
// (codeflow_test.go TestExchangeRejectsStateMismatch, TestExchangeRejectsNonce
// Mismatch). This file closes the exit-criterion seam: it wires the real
// verifier behind the real HTTP authentication middleware and proves that an
// expired / wrong-issuer / wrong-audience / bad-signature token and a missing
// token are all answered 401 — never a fallback identity (ARCH-005 §5).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// middlewareVerifier adapts the OIDC Verifier onto the httpapi.TokenVerifier
// port exactly as the server composition root does: the middleware
// authenticates only, so the first-login role seed is dropped at this
// boundary (ARCH-005 §2/§5).
type middlewareVerifier struct{ v *Verifier }

func (a middlewareVerifier) Verify(ctx context.Context, raw string) (domain.Identity, error) {
	id, err := a.v.Verify(ctx, raw)
	if err != nil {
		return domain.Identity{}, err
	}
	return domain.Identity{SubjectID: id.SubjectID, DisplayName: id.DisplayName, Email: id.Email}, nil
}

// TestI5aExitCriteriaTokenAndClaim proofs (d) end-to-end at the HTTP boundary.
func TestI5aExitCriteriaTokenAndClaim(t *testing.T) {
	p := newStubProvider(t)

	// The protected handler answers 200 only when the middleware authenticated.
	protected := httpapi.AuthenticationMiddleware(
		middlewareVerifier{v: p.newVerifier(t, roleMappings)},
		nil,
		httpapi.AuthOptions{},
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongIssuer := p.baseClaims()
	wrongIssuer["iss"] = "https://evil.example"
	wrongAudience := p.baseClaims()
	wrongAudience["aud"] = "another-client"
	expired := p.baseClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"valid", p.sign(p.baseClaims()), http.StatusOK},
		{"missing", "", http.StatusUnauthorized},
		{"expired", p.sign(expired), http.StatusUnauthorized},
		{"wrong issuer", p.sign(wrongIssuer), http.StatusUnauthorized},
		{"wrong audience", p.sign(wrongAudience), http.StatusUnauthorized},
		{"bad signature", p.signWith(otherKey, stubKid, p.baseClaims()), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// An unknown roles-claim value grants zero roles — fail closed, never a
	// crash (ARCH-005 §2); the same claim vocabulary the authorizer re-reads.
	v := p.newVerifier(t, roleMappings)
	claims := p.baseClaims()
	claims["roles"] = []string{"not-a-role"}
	id, err := v.Verify(context.Background(), p.sign(claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(id.Roles) != 0 {
		t.Fatalf("Roles = %v, want none for an unknown roles-claim value", id.Roles)
	}
}
