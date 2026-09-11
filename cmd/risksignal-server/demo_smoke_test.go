package main

// DEV-132 — ARCH-007 §8 / §4.4 step-5 demo smoke (loopback approximation).
//
// §4.4 step 5 of the implementation concept requires a smoke test that checks
// "Anmeldung, API, Quellenmonitor und einen lesenden Signalabruf": login, the
// API, the source monitor and one read-only signal retrieval. This test drives
// exactly that flow against the real product code:
//
//  1. login (mock OIDC) — the real Authorization Code + PKCE login of
//     internal/adapters/oidc runs against the mock OIDC provider
//     (cmd/mock-oidc's provider library); the resulting bearer access token
//     is the credential of every subsequent request;
//  2. API read — GET /api/v1/signals through the real composition root
//     (newHandler: the WP-1a.06 middleware chain + the I5a authentication
//     middleware + the generated routes) over a migrated, demo-seeded
//     database, authenticated only by the mock-OIDC token (no local bypass);
//  3. source monitor — `risksignal source status --output json`, the
//     ARCH-002 §5 monitor projection (the §4.4 "Quellenmonitor");
//  4. one signal read — GET /api/v1/signals/{id}, matching the list read.
//
// Loopback approximation, by design. The production demo overlay
// (deploy/demo/compose.yaml, DEV-131) terminates TLS in Caddy and serves the
// server behind it; a full container/TLS/ACME end to end is neither
// deterministic nor cheap in a developer/CI checkout. This smoke therefore
// exercises the same server binaries, the same authentication and the same
// application use cases over loopback HTTP (httptest), against the compose
// PostgreSQL and the mock OIDC provider — the flow §4.4 step 5 names, without
// the TLS termination the overlay adds on top. It skips when no PostgreSQL is
// reachable, like the other composition-root integration tests, so
// `go test ./...` stays green without the compose environment.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/mockoidc"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/oidc"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// smokeUserID is the fixed internal id of the smoke's provisioned analyst
// (the demo overlay's OIDC identities are provisioned out of band): a fixed
// literal so a repeated run upserts idempotently.
const smokeUserID = "e5a13200-0000-4000-8000-000000000001"

// TestDemoSmokeStep5Flow is the ARCH-007 §8 / §4.4 step-5 demo smoke.
func TestDemoSmokeStep5Flow(t *testing.T) {
	// Not parallel: newServerTestDB owns a single fixed scratch database, so
	// this test runs sequentially like the other newServerTestDB users.
	dbURL := newServerTestDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Migrate the fresh database with the real embedded migration set.
	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		_ = runner.Close()
		t.Fatalf("migrate: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	// Seed through the real operator path (`demo seed`, WP-1b.05): the
	// synthetic source is registered and run once, and the deterministic
	// reference signals the API read expects are produced.
	seedDemo(t, dbURL)

	pool, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.NewPool: %v", err)
	}
	t.Cleanup(pool.Close)

	// [1/4] login (mock OIDC): the real Authorization Code + PKCE flow of the
	// OIDC adapter against the mock provider yields a bearer access token.
	mock := startSmokeOIDC(t)
	tokens := smokeLogin(t, mock)
	if strings.TrimSpace(tokens.AccessToken) == "" {
		t.Fatal("login returned no access token")
	}
	subject := tokens.Identity.SubjectID
	if !strings.Contains(subject, "::") {
		t.Fatalf("login subject %q is not issuer-qualified", subject)
	}
	// Provision the internal user the verified token maps onto (the demo
	// overlay seeds real identities; the smoke seeds the mock subject with the
	// security_analyst role so the authenticated reads are permitted).
	provisionSmokeUser(t, ctx, dbURL, subject)

	// The server stack: the real composition root with the local bypass OFF —
	// the only credential is the mock-OIDC bearer token (the demo overlay's
	// posture). A valid loopback bind keeps the config self-consistent.
	cfg := config.Defaults()
	cfg.Env = "local"
	cfg.Database.URL = dbURL
	cfg.HTTP.Addr = "127.0.0.1:0"
	cfg.OIDC.Issuer = mock.Issuer()
	cfg.OIDC.ClientID = mock.ClientID
	cfg.Auth.BypassEnabled = false

	handler, err := newHandler(&cfg, pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// [2/4] API read: GET /api/v1/signals, authenticated by the mock-OIDC token.
	list := smokeListSignals(t, srv.URL, "/api/v1/signals?limit=100", tokens.AccessToken)
	if len(list.Data) != len(knownSignalCVEs) {
		t.Fatalf("GET /api/v1/signals returned %d signals, want %d (one demo seed)", len(list.Data), len(knownSignalCVEs))
	}
	if list.Data[0].CveID != knownSignalCVEs[0] {
		t.Fatalf("first signal = %q, want %q", list.Data[0].CveID, knownSignalCVEs[0])
	}

	// [3/4] source monitor: the ARCH-002 §5 projection through the operator
	// CLI must report the synthetic source and its completed run.
	smokeSourceMonitor(t, dbURL)

	// [4/4] one signal read: GET /api/v1/signals/{id}, matching the list read.
	first := list.Data[0]
	detail := smokeSignalDetail(t, srv.URL, "/api/v1/signals/"+first.ID, tokens.AccessToken)
	if detail.ID != first.ID || detail.CveID != first.CveID || detail.Priority != first.Priority {
		t.Fatalf("signal detail %+v does not match the list read %+v", detail, first)
	}

	t.Logf("demo smoke (§4.4 step 5): login (mock OIDC) → %d signals → source monitor → signal %s (%s %s)",
		len(list.Data), first.ID, first.CveID, first.Priority)
}

// startSmokeOIDC starts the mock OIDC provider (the same library behind
// cmd/mock-oidc) on a loopback listener and returns it (torn down with the
// test). Its discovery/advertised issuer stems from that listener, so the
// server and the login flow agree on the issuer without any hostname mapping.
func startSmokeOIDC(t *testing.T) *mockoidc.MockOIDC {
	t.Helper()
	m, err := mockoidc.NewServer(nil)
	if err != nil {
		t.Fatalf("mockoidc.NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock OIDC: %v", err)
	}
	if err := m.Start(ln, nil); err != nil {
		t.Fatalf("start mock OIDC: %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })
	return m
}

// smokeLogin runs the real Authorization Code + PKCE loopback login against
// the mock provider and returns the verified token set. The mock's authorize
// endpoint immediately redirects to the loopback callback with a code (no
// interactive page), so the flow completes deterministically.
func smokeLogin(t *testing.T, m *mockoidc.MockOIDC) oidc.Tokens {
	t.Helper()
	v, err := oidc.New(oidc.Config{
		Issuer:       m.Issuer(),
		ClientID:     m.ClientID,
		ClientSecret: m.ClientSecret,
		RedirectURL:  "http://127.0.0.1/callback",
		Scopes:       []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen callback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	open := func(authURL string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
		if err != nil {
			return err
		}
		// The mock redirects straight to the loopback callback; following it
		// completes the browser half of the flow.
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	tokens, err := v.LoopbackLoginWithTokens(ctx, ln, open)
	if err != nil {
		t.Fatalf("mock OIDC login: %v", err)
	}
	return tokens
}

// provisionSmokeUser upserts the internal user (and its security_analyst
// grant) for the verified token subject. It is idempotent: the fixed id and
// the subject-uq upsert make a repeated run a no-op.
func provisionSmokeUser(t *testing.T, ctx context.Context, dbURL, subject string) {
	t.Helper()
	pool, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.NewPool (provision): %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, subject_id, display_name, created_at, updated_at)
		 VALUES ($1, $2, 'Demo Smoke Analyst', now(), now())
		 ON CONFLICT (subject_id) DO NOTHING`,
		smokeUserID, subject); err != nil {
		t.Fatalf("provision smoke user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, granted_at, granted_by)
		 VALUES ($1, 'security_analyst', now(), 'seed')
		 ON CONFLICT DO NOTHING`,
		smokeUserID); err != nil {
		t.Fatalf("provision smoke user role: %v", err)
	}
}

// smokeSignal is one signal as the list and detail reads render it; the smoke
// reads the fields it asserts on.
type smokeSignal struct {
	ID       string `json:"id"`
	CveID    string `json:"cve_id"`
	Priority string `json:"priority"`
	Status   string `json:"status"`
}

// smokeSignalPage is the {data, next_cursor} page envelope of the list read.
type smokeSignalPage struct {
	Data       []smokeSignal `json:"data"`
	NextCursor *string       `json:"next_cursor"`
}

// smokeGET performs an authenticated GET and returns the response body (200).
func smokeGET(t *testing.T, base, path, token string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("build request %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", path, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", path, err)
	}
	return body
}

// smokeListSignals performs the authenticated list read and decodes the page.
func smokeListSignals(t *testing.T, base, path, token string) smokeSignalPage {
	t.Helper()
	body := smokeGET(t, base, path, token)
	var page smokeSignalPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return page
}

// smokeSignalDetail performs the authenticated single-signal read and decodes
// the single Signal the endpoint returns.
func smokeSignalDetail(t *testing.T, base, path, token string) smokeSignal {
	t.Helper()
	body := smokeGET(t, base, path, token)
	var s smokeSignal
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return s
}

// smokeSourceMonitor runs `risksignal source status --output json` (the
// ARCH-002 §5 monitor projection) against the demo database and asserts the
// synthetic source with its completed run is reported.
func smokeSourceMonitor(t *testing.T, dbURL string) {
	t.Helper()
	bin := demoSeedBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//nolint:gosec // G204: bin is the CLI this package's test built; the
	// argument list is constant and the target database is this test's own
	// scratch database.
	cmd := exec.CommandContext(ctx, bin, "source", "status", "--output", "json")
	cmd.Env = cliEnv(dbURL)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("source status failed: %v (%s)", err, out)
	}

	var env struct {
		Status string `json:"status"`
		Result struct {
			Sources []struct {
				SourceID string `json:"source_id"`
				Type     string `json:"type"`
				Name     string `json:"name"`
				LastRun  *struct {
					Status string `json:"status"`
				} `json:"last_run"`
			} `json:"sources"`
		} `json:"result"`
		Error *struct {
			Class   string `json:"class"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode source status envelope from %q: %v", out, err)
	}
	if env.Status != "ok" {
		t.Fatalf("source status status = %q (err %+v)", env.Status, env.Error)
	}
	if len(env.Result.Sources) == 0 {
		t.Fatal("source monitor reported no sources after the demo seed")
	}
	var synthetic *struct {
		SourceID string `json:"source_id"`
		Type     string `json:"type"`
		Name     string `json:"name"`
		LastRun  *struct {
			Status string `json:"status"`
		} `json:"last_run"`
	}
	for i := range env.Result.Sources {
		if env.Result.Sources[i].Type == "synthetic" {
			synthetic = &env.Result.Sources[i]
			break
		}
	}
	if synthetic == nil {
		t.Fatalf("source monitor did not report the synthetic source: %+v", env.Result.Sources)
	}
	if synthetic.LastRun == nil {
		t.Fatalf("source monitor reports the synthetic source with no run — the demo seed run is not visible")
	}
	// The demo seed's deterministic run closes 'failed' with the one malformed
	// E1 case counted (ARCH-001 §3): the monitor must surface the real outcome.
	if synthetic.LastRun.Status != "failed" {
		t.Fatalf("source monitor synthetic run status = %q, want failed (E1 counted)", synthetic.LastRun.Status)
	}
}
