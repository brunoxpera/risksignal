package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// writeJSON writes v as a JSON response body.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// newAuthReq builds a fresh AuthRequest for the stub.
func newAuthReq(t *testing.T, v *Verifier) AuthRequest {
	t.Helper()
	req, err := v.NewAuthRequest("https://app.local/callback")
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	return req
}

func TestNewAuthRequestGeneratesStateNonceAndPKCE(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)

	req := newAuthReq(t, v)
	if req.State == "" || req.Nonce == "" || req.CodeVerifier == "" {
		t.Fatalf("AuthRequest has empty members: %+v", req)
	}
	if req.State == req.Nonce || req.State == req.CodeVerifier || req.Nonce == req.CodeVerifier {
		t.Error("AuthRequest members are not distinct")
	}
	if req.RedirectURL != "https://app.local/callback" {
		t.Errorf("RedirectURL = %q", req.RedirectURL)
	}

	other := newAuthReq(t, v)
	if other.State == req.State || other.Nonce == req.Nonce {
		t.Error("two AuthRequests reused state/nonce")
	}
}

func TestAuthorizationURL(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	req := newAuthReq(t, v)

	raw, err := v.AuthorizationURL(context.Background(), req)
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("client_id") != stubClientID {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), stubClientID)
	}
	if q.Get("state") != req.State || q.Get("nonce") != req.Nonce {
		t.Error("state/nonce not carried in the authorization URL")
	}
	if q.Get("code_challenge") != codeChallenge(req.CodeVerifier) {
		t.Error("code_challenge is not the S256 challenge of the verifier")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("redirect_uri") != req.RedirectURL {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), req.RedirectURL)
	}
}

func TestExchangeRejectsStateMismatch(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	req := newAuthReq(t, v)

	called := false
	p.token = func(w http.ResponseWriter, _ *http.Request) {
		called = true
		writeJSON(t, w, map[string]string{"id_token": "unused"})
	}

	_, err := v.Exchange(context.Background(), "code-1", "wrong-state", req)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Exchange err = %v, want ErrInvalidToken", err)
	}
	if called {
		t.Error("token endpoint called despite the state mismatch")
	}
}

func TestExchangeRejectsNonceMismatch(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	req := newAuthReq(t, v)

	claims := p.baseClaims()
	claims["nonce"] = "some-other-nonce"
	idToken := p.sign(claims)
	p.token = func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]string{"id_token": idToken, "access_token": "at"})
	}

	_, err := v.Exchange(context.Background(), "code-1", req.State, req)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Exchange err = %v, want ErrInvalidToken", err)
	}
}

func TestExchangeRejectsProviderError(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	req := newAuthReq(t, v)

	p.token = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]string{"error": "invalid_grant"})
	}

	_, err := v.Exchange(context.Background(), "code-1", req.State, req)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Exchange err = %v, want ErrInvalidToken", err)
	}
}

func TestExchangeForwardsPKCEAndRoundTrips(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	req := newAuthReq(t, v)

	var gotVerifier, gotCode string
	p.token = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotVerifier = r.Form.Get("code_verifier")
		gotCode = r.Form.Get("code")
		claims := p.baseClaims()
		claims["nonce"] = req.Nonce
		writeJSON(t, w, map[string]string{
			"id_token":     p.sign(claims),
			"access_token": "at",
			"token_type":   "bearer",
		})
	}

	ident, err := v.Exchange(context.Background(), "code-1", req.State, req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotVerifier != req.CodeVerifier {
		t.Errorf("code_verifier = %q, want the PKCE verifier", gotVerifier)
	}
	if gotCode != "code-1" {
		t.Errorf("code = %q, want code-1", gotCode)
	}
	if ident.SubjectID != p.issuer()+"::user-1" {
		t.Errorf("SubjectID = %q, want the issuer-qualified subject", ident.SubjectID)
	}
	if len(ident.Roles) != 1 || ident.Roles[0] != domain.RoleSecurityAnalyst {
		t.Errorf("Roles = %v, want [%s]", ident.Roles, domain.RoleSecurityAnalyst)
	}
}

// TestLoopbackLogin drives the full CLI browser flow over a loopback callback:
// the stub authorization endpoint redirects to the callback with a code and
// state, and the login completes with the mapped identity.
func TestLoopbackLogin(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)

	var capturedNonce string
	p.auth = func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		capturedNonce = q.Get("nonce")
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect", http.StatusBadRequest)
			return
		}
		rq := redirect.Query()
		rq.Set("code", "loopback-code")
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		// #nosec G710 — test stub: the redirect target is the loopback
		// callback the test itself supplied, never untrusted input.
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	}
	p.token = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims := p.baseClaims()
		claims["nonce"] = capturedNonce
		writeJSON(t, w, map[string]string{"id_token": p.sign(claims), "access_token": "at"})
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	open := func(authURL string) error {
		// #nosec G107 — test: authURL is the URL the verifier just built.
		resp, err := http.Get(authURL)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	ident, err := v.LoopbackLogin(context.Background(), ln, open)
	if err != nil {
		t.Fatalf("LoopbackLogin: %v", err)
	}
	if ident.SubjectID != p.issuer()+"::user-1" {
		t.Errorf("SubjectID = %q, want the issuer-qualified subject", ident.SubjectID)
	}
	if len(ident.Roles) != 1 || ident.Roles[0] != domain.RoleSecurityAnalyst {
		t.Errorf("Roles = %v, want [%s]", ident.Roles, domain.RoleSecurityAnalyst)
	}
}

// TestWaitForCallbackRejectsStateMismatch proves the loopback callback enforces
// the CSRF state.
func TestWaitForCallbackRejectsStateMismatch(t *testing.T) {
	p := newStubProvider(t)
	v := p.newVerifier(t, roleMappings)
	req := newAuthReq(t, v)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	errs := make(chan error, 1)
	go func() {
		_, err := v.WaitForCallback(context.Background(), ln, req)
		errs <- err
	}()

	callback := "http://" + ln.Addr().String() + callbackPath + "?code=x&state=wrong"
	// #nosec G107 — test: callback is the loopback listener just opened.
	resp, err := http.Get(callback)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = resp.Body.Close()

	if err := <-errs; !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("WaitForCallback err = %v, want ErrInvalidToken", err)
	}
}
