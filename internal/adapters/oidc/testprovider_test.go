package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Stub issuer constants shared by the tests.
const (
	stubClientID     = "client-1"
	stubClientSecret = "s3cret-value"
	stubKid          = "test-key-1"
)

// stubProvider is an in-process OIDC issuer for the unit tests: it serves a
// discovery document and a JWKS over httptest and signs tokens with a
// generated RSA key. The token/authorize/device endpoints are swappable per
// test; the JWKS is mutable so a rotation can be simulated.
type stubProvider struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	jwks       []jwk // served at /jwks
	omitDevice bool  // omit device_authorization_endpoint from discovery
	token      http.HandlerFunc
	auth       http.HandlerFunc
	device     http.HandlerFunc
}

func newStubProvider(t *testing.T) *stubProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := &stubProvider{t: t, key: key}
	p.jwks = []jwk{publicJWK(stubKid, &key.PublicKey)}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/jwks", p.handleJWKS)
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if p.token == nil {
			http.Error(w, "no token handler", http.StatusNotFound)
			return
		}
		p.token(w, r)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if p.auth == nil {
			http.Error(w, "no authorization handler", http.StatusNotFound)
			return
		}
		p.auth(w, r)
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		if p.device == nil {
			http.Error(w, "no device handler", http.StatusNotFound)
			return
		}
		p.device(w, r)
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// issuer is the stub issuer base URL (no trailing slash).
func (p *stubProvider) issuer() string { return p.srv.URL }

// config returns an adapter configuration pointed at the stub; mods can extend
// it (role mappings, audience, …).
func (p *stubProvider) config(mods ...func(*Config)) Config {
	c := Config{
		Issuer:       p.srv.URL,
		ClientID:     stubClientID,
		ClientSecret: stubClientSecret,
		RedirectURL:  "https://app.local/callback",
	}
	for _, m := range mods {
		m(&c)
	}
	return c
}

// newVerifier builds a Verifier over the stub.
func (p *stubProvider) newVerifier(t *testing.T, mods ...func(*Config)) *Verifier {
	t.Helper()
	v, err := New(p.config(mods...))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// handleDiscovery serves a discovery document whose URLs follow the request
// host, so the document is self-consistent.
func (p *stubProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	base := "http://" + r.Host
	doc := map[string]any{
		"issuer":                 base,
		"authorization_endpoint": base + "/authorize",
		"token_endpoint":         base + "/token",
		"jwks_uri":               base + "/jwks",
		"userinfo_endpoint":      base + "/userinfo",
	}
	if !p.omitDevice {
		doc["device_authorization_endpoint"] = base + "/device"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// handleJWKS serves the current key set.
func (p *stubProvider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwksDocument{Keys: p.jwks})
}

// baseClaims is a valid token payload: correct issuer, audience, validity
// window, subject/name/e-mail and a mapped roles value.
func (p *stubProvider) baseClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   p.issuer(),
		"aud":   stubClientID,
		"sub":   "user-1",
		"name":  "Ada Lovelace",
		"email": "ada@example.com",
		"roles": []string{"analysts"},
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
	}
}

// sign returns a token with the stub key and kid.
func (p *stubProvider) sign(claims jwt.MapClaims) string {
	return p.signWith(p.key, stubKid, claims)
}

// signWith returns a token signed with an arbitrary key and kid (bad-signature
// and unknown-kid cases).
func (p *stubProvider) signWith(key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	p.t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		p.t.Fatalf("sign token: %v", err)
	}
	return signed
}

// publicJWK renders the public part of an RSA key as a JWK.
func publicJWK(kid string, pub *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
