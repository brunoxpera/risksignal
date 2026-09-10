package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// fakeVerifier is a TokenVerifier whose behaviour is a plain function.
type fakeVerifier struct {
	fn func(raw string) (domain.Identity, error)
}

func (f fakeVerifier) Verify(_ context.Context, raw string) (domain.Identity, error) {
	return f.fn(raw)
}

// fakeSessions is a SessionResolver whose behaviour is a plain function.
type fakeSessions struct {
	fn func(id string) (domain.Identity, error)
}

func (f fakeSessions) Resolve(_ context.Context, id string) (domain.Identity, error) {
	return f.fn(id)
}

// identifyHandler records the identity the middleware placed in the context
// and answers 200.
func identifyHandler(t *testing.T, got *domain.Identity, present *bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got, *present = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUnauthenticatedRequestIs401(t *testing.T) {
	verifier := fakeVerifier{fn: func(string) (domain.Identity, error) { return domain.Identity{}, errors.New("nope") }}
	h := AuthenticationMiddleware(verifier, nil, AuthOptions{SessionCookieName: "sid"})(okHandler())

	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
	p := decodeProblem(t, rec)
	if p.Status != http.StatusUnauthorized || p.Title != titleUnauthorized {
		t.Errorf("problem = %+v, want 401 %q", p, titleUnauthorized)
	}
}

func TestBearerTokenAuthenticates(t *testing.T) {
	want := domain.Identity{SubjectID: "iss::alice", DisplayName: "Alice", Email: "alice@example.com"}
	verifier := fakeVerifier{fn: func(raw string) (domain.Identity, error) {
		if raw != "good-token" {
			return domain.Identity{}, errors.New("bad token")
		}
		return want, nil
	}}
	var got domain.Identity
	var present bool
	h := AuthenticationMiddleware(verifier, nil, AuthOptions{})(identifyHandler(t, &got, &present))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := do(h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !present || got != want {
		t.Errorf("identity = %+v (present=%v), want %+v", got, present, want)
	}
}

func TestInvalidBearerTokenIs401(t *testing.T) {
	verifier := fakeVerifier{fn: func(string) (domain.Identity, error) { return domain.Identity{}, errors.New("expired") }}
	h := AuthenticationMiddleware(verifier, nil, AuthOptions{})(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	req.Header.Set("Authorization", "Bearer expired")
	if rec := do(h, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestMalformedAuthorizationIs401 covers a non-Bearer scheme and an empty
// token: both are anonymous.
func TestMalformedAuthorizationIs401(t *testing.T) {
	verifier := fakeVerifier{fn: func(string) (domain.Identity, error) { return domain.Identity{SubjectID: "x"}, nil }}
	h := AuthenticationMiddleware(verifier, nil, AuthOptions{})(okHandler())
	for _, header := range []string{"Basic dXNlcjpwYXNz", "Bearer ", "Bearer", "token"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
		req.Header.Set("Authorization", header)
		if rec := do(h, req); rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status = %d, want 401", header, rec.Code)
		}
	}
}

func TestPublicPathsAreExempt(t *testing.T) {
	// A verifier that always fails proves the middleware never even tries.
	verifier := fakeVerifier{fn: func(string) (domain.Identity, error) { return domain.Identity{}, errors.New("no") }}
	var present bool
	var got domain.Identity
	h := AuthenticationMiddleware(verifier, nil, AuthOptions{})(identifyHandler(t, &got, &present))

	for _, path := range []string{"/health", "/health/live", "/health/ready", "/version", "/auth", "/auth/login", "/auth/callback"} {
		present = true
		rec := do(h, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("public path %q answered 401", path)
		}
		if present {
			t.Errorf("public path %q carried an identity, want none", path)
		}
	}

	for _, path := range []string{"/api/v1/signals", "/login", "/healthish"} {
		if IsPublicPath(path) {
			t.Errorf("IsPublicPath(%q) = true, want false", path)
		}
	}
}

func TestBypassAuthenticatesAsLocalDevPrincipal(t *testing.T) {
	var got domain.Identity
	var present bool
	h := AuthenticationMiddleware(nil, nil, AuthOptions{BypassEnabled: true})(identifyHandler(t, &got, &present))

	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !present {
		t.Fatal("no identity in context with the bypass on")
	}
	if got.SubjectID != "local::local-developer" || got.DisplayName != "local-developer" {
		t.Errorf("identity = %+v, want subject local::local-developer", got)
	}

	// The bypass wins even when a token is present (the process is local +
	// loopback, the token is irrelevant).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	req.Header.Set("Authorization", "Bearer whatever")
	got, present = domain.Identity{}, false
	if rec := do(h, req); rec.Code != http.StatusOK || !present || got.SubjectID != "local::local-developer" {
		t.Errorf("bypass with a token: code=%d identity=%+v", rec.Code, got)
	}
}

func TestBypassPrincipalOverride(t *testing.T) {
	var got domain.Identity
	var present bool
	h := AuthenticationMiddleware(nil, nil, AuthOptions{BypassEnabled: true, BypassPrincipal: "alice"})(identifyHandler(t, &got, &present))
	do(h, httptest.NewRequest(http.MethodGet, "/x", nil))
	if got.SubjectID != "local::alice" {
		t.Errorf("subject = %q, want local::alice", got.SubjectID)
	}
}

func TestSessionCookieResolves(t *testing.T) {
	want := domain.Identity{SubjectID: "iss::bob", DisplayName: "Bob"}
	sessions := fakeSessions{fn: func(id string) (domain.Identity, error) {
		if id != "sid-123" {
			return domain.Identity{}, errors.New("unknown session")
		}
		return want, nil
	}}
	var got domain.Identity
	var present bool
	h := AuthenticationMiddleware(
		fakeVerifier{fn: func(string) (domain.Identity, error) { return domain.Identity{}, errors.New("no token") }},
		sessions,
		AuthOptions{SessionCookieName: "rs_session"},
	)(identifyHandler(t, &got, &present))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	req.AddCookie(testSessionCookie("rs_session", "sid-123"))
	if rec := do(h, req); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !present || got != want {
		t.Errorf("identity = %+v, want %+v", got, want)
	}

	// An unknown session id is anonymous.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	req.AddCookie(testSessionCookie("rs_session", "bogus"))
	if rec := do(h, req); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown session: status = %d, want 401", rec.Code)
	}
}

func TestSessionCookieIgnoredWithoutResolver(t *testing.T) {
	verifier := fakeVerifier{fn: func(string) (domain.Identity, error) { return domain.Identity{}, errors.New("no token") }}
	h := AuthenticationMiddleware(verifier, nil, AuthOptions{SessionCookieName: "rs_session"})(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	req.AddCookie(testSessionCookie("rs_session", "sid-123"))
	if rec := do(h, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no resolver wired)", rec.Code)
	}
}

func TestAuthenticationMiddlewarePanicsWithoutVerifier(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("AuthenticationMiddleware did not panic without a verifier and the bypass off")
		}
	}()
	AuthenticationMiddleware(nil, nil, AuthOptions{})
}

// TestAuthFailureCarriesChainContext proves the 401 of an unauthenticated
// request still carries the correlation id of the WP-1a.06 chain.
func TestAuthFailureCarriesChainContext(t *testing.T) {
	logger, _ := testLogger(t)
	verifier := fakeVerifier{fn: func(string) (domain.Identity, error) { return domain.Identity{}, errors.New("no") }}
	auth := AuthenticationMiddleware(verifier, nil, AuthOptions{})
	h := NewHandlerWithAuth(okHandler(), logger, auth)

	rec := do(h, httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Error("401 response is missing the X-Request-ID correlation header")
	}
	p := decodeProblem(t, rec)
	if p.CorrelationId == "" || p.CorrelationId == "-" {
		t.Errorf("problem correlation_id = %q, want the request id", p.CorrelationId)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("401 response is missing the security headers of the chain")
	}
}

// testSessionCookie builds a session cookie for the request-side tests. The
// security attributes satisfy the linter; the middleware only reads the value.
func testSessionCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
