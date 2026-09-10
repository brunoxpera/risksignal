package main

// Tests of the WP-1a.07 wiring at the composition root: the System routes on
// the real ServeMux behind the full WP-1a.06 middleware chain, probed with
// the real pool and migration runner.
//
// Exit criterion WP-1a.07: with the database stopped, readiness is red
// (503) while liveness stays green (200), and /version shows the build
// values. The DB-down case needs no PostgreSQL: a pool pointing at a closed
// local port refuses instantly. The DB-up case runs against a real,
// short-lived PostgreSQL and skips when none is reachable, so `go test
// ./...` stays green on machines without the compose environment (the
// scratch-database pattern of cmd/risksignal/main_test.go).

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/platform/buildinfo"
	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// embeddedVersions returns the versions of the embedded migration files in
// application order (the leading number of each <version>_<name>.sql file
// name). The migration assertions treat the embedded set as the source of
// truth instead of a hard-coded count, so they stay correct as the set grows.
func embeddedVersions(t *testing.T) []int64 {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	versions := make([]int64, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			t.Fatalf("migration file %q has no version prefix", name)
		}
		v, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatalf("migration file %q: invalid version prefix: %v", name, err)
		}
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions
}

// defaultTestDBURL points at the compose db service (compose.yaml, WP-1a.03).
const defaultTestDBURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// testConfig returns a valid local configuration for the given database URL.
// It enables the local authentication bypass (valid: env=local, loopback
// bind) so the composition-root tests exercise the real route table as the
// seeded dev principal without an OIDC provider.
func testConfig(dbURL string) *config.Config {
	cfg := config.Defaults()
	cfg.Env = "local"
	cfg.HTTP = config.HTTP{Addr: "127.0.0.1:0"}
	cfg.Database = config.Database{URL: dbURL}
	cfg.OIDC.Issuer = "http://127.0.0.1:9000/oidc"
	cfg.Auth.BypassEnabled = true
	return &cfg
}

// discardLogger keeps the middleware chain quiet in tests. The chain takes a
// structured *slog.Logger since WP-1a.08; discarding output keeps the log
// assertions of the httpapi package, not here.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// closedAddr returns a host:port on which nothing listens. A listener is
// opened and closed again so the port is virtually certain to refuse
// connections — the deterministic stand-in for "database stopped".
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve closed port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return addr
}

// readyBody is the JSON body of GET /health/ready as the composition-root
// tests decode it (the httpapi.readyReport type is unexported).
type readyBody struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func decodeReady(t *testing.T, rec *httptest.ResponseRecorder) readyBody {
	t.Helper()
	var body readyBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s body %q: %v", "/health/ready", rec.Body.String(), err)
	}
	return body
}

// TestHealthWithDatabaseDown drives the WP-1a.07 exit criterion without a
// real database: the pool targets a closed local port, so every database
// probe refuses instantly — /health/ready is 503 with distinct reasons for
// the database and the migration state, while /health/live stays 200 and
// /version reports the build metadata.
func TestHealthWithDatabaseDown(t *testing.T) {
	addr := closedAddr(t)
	cfg := testConfig("postgres://risksignal:risksignal@" + addr + "/risksignal?sslmode=disable")

	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		t.Fatalf("postgres.NewPool: %v", err)
	}
	defer pool.Close()
	h, err := newHandler(cfg, pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	live := get(t, h, "/health/live")
	if live.Code != http.StatusOK {
		t.Errorf("/health/live status = %d, want 200 (liveness stays green)", live.Code)
	}

	ready := get(t, h, "/health/ready")
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("/health/ready status = %d, want 503 (body: %s)", ready.Code, ready.Body.String())
	}
	body := decodeReady(t, ready)
	if body.Status != "not_ready" {
		t.Errorf("ready status field = %q, want %q", body.Status, "not_ready")
	}
	// Distinct reasons per failing check: the database check names the
	// unreachable database, the migrations check cannot inspect the state,
	// and the configuration — the only criterion independent of the
	// database — stays green.
	if body.Checks["database"] == "" || body.Checks["database"] == "ok" {
		t.Errorf("checks[database] = %q, want a failure reason", body.Checks["database"])
	}
	if body.Checks["migrations"] == "" || body.Checks["migrations"] == "ok" {
		t.Errorf("checks[migrations] = %q, want a failure reason", body.Checks["migrations"])
	}
	if body.Checks["migrations"] == body.Checks["database"] {
		t.Errorf("database and migrations reasons must be distinct, both are %q", body.Checks["database"])
	}
	if got := body.Checks["config"]; got != "ok" {
		t.Errorf("checks[config] = %q, want %q", got, "ok")
	}

	version := get(t, h, "/version")
	if version.Code != http.StatusOK {
		t.Fatalf("/version status = %d, want 200", version.Code)
	}
	var info buildinfo.Info
	if err := json.Unmarshal(version.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode /version body: %v", err)
	}
	if info != buildinfo.Current() {
		t.Errorf("/version = %+v, want the build metadata %+v", info, buildinfo.Current())
	}
}

// TestHealthReadyWithMigratedDatabase is the green path against a real
// PostgreSQL: a fresh database is migrated with the embedded migration set,
// after which every readiness criterion passes — /health/ready is 200 with
// all checks "ok" while liveness stays 200. Tests skip when no PostgreSQL
// is reachable.
func TestHealthReadyWithMigratedDatabase(t *testing.T) {
	dbURL := newServerTestDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("migrate fresh database: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}
	if len(res.Applied) != len(embeddedVersions(t)) {
		t.Fatalf("fresh migrate applied %d migration(s), want the full embedded set", len(res.Applied))
	}

	pool, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.NewPool: %v", err)
	}
	defer pool.Close()

	h, err := newHandler(testConfig(dbURL), pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	live := get(t, h, "/health/live")
	if live.Code != http.StatusOK {
		t.Errorf("/health/live status = %d, want 200", live.Code)
	}

	ready := get(t, h, "/health/ready")
	if ready.Code != http.StatusOK {
		t.Fatalf("/health/ready status = %d, want 200 (body: %s)", ready.Code, ready.Body.String())
	}
	body := decodeReady(t, ready)
	if body.Status != "ready" {
		t.Errorf("ready status field = %q, want %q", body.Status, "ready")
	}
	for _, name := range []string{"database", "migrations", "config"} {
		if got := body.Checks[name]; got != "ok" {
			t.Errorf("checks[%s] = %q, want %q", name, got, "ok")
		}
	}
}

// newServerTestDB creates a dedicated database for one test case and
// registers its removal, skipping when no PostgreSQL is reachable (same
// pattern as cmd/risksignal/main_test.go; duplicated because test helpers
// cannot be shared across packages).
func newServerTestDB(t *testing.T) string {
	t.Helper()
	adminURL := os.Getenv("RISKSIGNAL_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = defaultTestDBURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Skipf("integration database unavailable: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Skipf("integration database not reachable (set RISKSIGNAL_TEST_DATABASE_URL): %v", err)
	}

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("parse admin url: %v", err)
	}
	name := "risksignal_server_it"
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
		t.Fatalf("reset test database: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
			t.Errorf("drop test database %s: %v", name, err)
		}
	})

	u.Path = "/" + name
	return u.String()
}

// TestUnauthenticatedRequestReturns401 proves the I5a authentication
// middleware at the composition root (ARCH-005 §5): with no credentials an
// API request is answered 401 with an RFC 9457 problem detail — before any
// use case or database access — while the public probes stay open. The OIDC
// verifier is built (bypass off, client id set) but never consulted.
func TestUnauthenticatedRequestReturns401(t *testing.T) {
	cfg := testConfig("postgres://risksignal:risksignal@" + closedAddr(t) + "/risksignal?sslmode=disable")
	cfg.Auth.BypassEnabled = false
	cfg.OIDC.ClientID = "risksignal-web"

	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		t.Fatalf("postgres.NewPool: %v", err)
	}
	defer pool.Close()

	h, err := newHandler(cfg, pool, discardLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	rec := get(t, h, "/api/v1/signals")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/v1/signals status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	var p struct {
		Status        int    `json:"status"`
		Title         string `json:"title"`
		CorrelationId string `json:"correlation_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode 401 problem detail %q: %v", rec.Body.String(), err)
	}
	if p.Status != http.StatusUnauthorized || p.Title != "Unauthorized" || p.CorrelationId == "" {
		t.Errorf("401 problem = %+v, want status 401, title Unauthorized, correlation id", p)
	}
	if rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", rec.Header().Get("WWW-Authenticate"))
	}

	// The public probes need no credentials.
	if live := get(t, h, "/health/live"); live.Code != http.StatusOK {
		t.Errorf("/health/live status = %d, want 200 (public)", live.Code)
	}
	if version := get(t, h, "/version"); version.Code != http.StatusOK {
		t.Errorf("/version status = %d, want 200 (public)", version.Code)
	}
}

// TestNewHandlerFailsOnInvalidOIDCConfig proves a misconfigured oidc.* block
// fails at handler construction — before the process binds — when the local
// bypass is off.
func TestNewHandlerFailsOnInvalidOIDCConfig(t *testing.T) {
	cfg := testConfig("postgres://risksignal:risksignal@" + closedAddr(t) + "/risksignal?sslmode=disable")
	cfg.Auth.BypassEnabled = false
	cfg.OIDC.ClientID = "" // mandatory once the bypass is off

	pool, err := postgres.NewPool(context.Background(), cfg.Database.URL)
	if err != nil {
		t.Fatalf("postgres.NewPool: %v", err)
	}
	defer pool.Close()

	if _, err := newHandler(cfg, pool, discardLogger()); err == nil {
		t.Fatal("newHandler succeeded with a missing oidc.client_id, want error")
	}
}
