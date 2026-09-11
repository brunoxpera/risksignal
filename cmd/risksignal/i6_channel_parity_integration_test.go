package main

// I6 exit-criterion proof: cross-channel parity for the export and retention
// surfaces (ARCH-007 §1.1/§2.2, WP-6.07 / DEV-119, NFR-013).
//
// One export creation and one retention dry-run are driven through the two
// channels — the generated HTTP API (POST /api/v1/exports and
// POST /api/v1/retention/runs over httptest) and the in-process CLI
// (`export create`, `maintenance retention --dry-run`) — against the same
// migrated scratch database. The observable domain effect must be identical:
// both channels freeze the same filter/format and schedule exactly one
// export.generate job, and both store the same counts-only retention report;
// a non-Administrator is denied on both (403 / exit 4). Only the channel-local
// identifiers and clock-derived timestamps differ (the CLI drives the real
// clock; the API an injected fake clock). The test skips when no PostgreSQL is
// reachable (newTestDB), like every other integration test.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// i6ParityAdminSubject is the seeded administrator subject (migration 00009)
// the CLI --as flag carries (issuer-qualified); the API bypass takes the bare
// subject and prefixes the local namespace itself.
const i6ParityAdminSubject = "local::administrator"

// i6ParityAnalystSubject is the seeded single-role analyst subject; it holds no
// retention.manage, so the retention surface is denied for it on every channel.
const i6ParityAnalystSubject = "local::security-analyst"

// The bare bypass principals the API stack authenticates as (the middleware
// prefixes the local namespace: "administrator" -> "local::administrator").
const (
	i6ParityBypassAdmin   = "administrator"
	i6ParityBypassAnalyst = "security-analyst"
)

// newI6APIStack builds the HTTP API over the real service, mounting the I6
// surfaces behind the same authentication middleware (the local-bypass
// principal stands in for the token).
func newI6APIStack(t *testing.T, svc *application.Service, principal string) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	gate := httpapi.NewPermissionGate(nil, logger)
	httpapi.RegisterAPIRoutes(gate.Decorate(mux), httpapi.NewAPIHandler(svc, svc, svc, logger,
		httpapi.APISurfaces{Inventory: svc, Assets: svc, Users: svc, Exports: svc, Retention: svc, LegalHolds: svc}))
	auth := httpapi.AuthenticationMiddleware(nil, nil, httpapi.AuthOptions{BypassEnabled: true, BypassPrincipal: principal})
	srv := httptest.NewServer(auth(mux))
	t.Cleanup(srv.Close)
	return srv
}

// i6PostJSON posts a JSON body to url and returns the status and decoded body.
func i6PostJSON(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// i6SeedClosedSignal seeds one closed signal due for retention (a resolved
// signal closed six years before base) and returns its id.
func i6SeedClosedSignal(t *testing.T, pool *pgxpool.Pool, base time.Time, matchID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO risk_signals (match_id, priority, status, closed_at, rule_version, factors, created_at)
		 VALUES ($1, 'P3', 'resolved', $2, 'i1b-1', '{}'::jsonb, $3) RETURNING id`,
		matchID, base.AddDate(-6, 0, 0), base).Scan(&id); err != nil {
		t.Fatalf("seed closed signal: %v", err)
	}
	return id
}

// TestI6ExportChannelParity: the API and the CLI freeze the same filter/format,
// store the same pending export and enqueue exactly one export.generate job;
// a stale-authority analyst is denied nothing here (all roles hold
// exports.create) so the strong assertion is the converging state.
func TestI6ExportChannelParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	if code, _, stderr := runCLI(t, env, "maintenance", "migrate"); code != exitOK {
		t.Fatalf("migrate exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)

	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	cfg := config.Defaults()
	svc := newAppService(&cfg, pool, clock.NewFakeClock(base))
	srv := newI6APIStack(t, svc, i6ParityBypassAdmin)

	// API channel.
	apiStatus, apiBody := i6PostJSON(t, srv.URL+"/api/v1/exports", `{"filter":{"priority":"P1"},"format":"csv"}`)
	if apiStatus != http.StatusOK {
		t.Fatalf("API export status = %d, want 200 (%v)", apiStatus, apiBody)
	}
	apiID, _ := apiBody["id"].(string)
	if apiID == "" {
		t.Fatalf("API export returned no id (%v)", apiBody)
	}

	// CLI channel.
	code, stdout, stderr := runCLI(t, env, "export", "create", "--format", "csv", "--priority", "P1",
		"--as", i6ParityAdminSubject, "--output", "json")
	if code != exitOK {
		t.Fatalf("CLI export exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	cliEnv := decodeEnvelope(t, stdout)
	var cliResult struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(cliEnv.Result, &cliResult); err != nil {
		t.Fatalf("decode CLI export result: %v (%s)", err, string(cliEnv.Result))
	}
	if cliResult.ID == "" {
		t.Fatalf("CLI export returned no id (%s)", string(cliEnv.Result))
	}

	// Both rows converge: pending, csv, P1 filter, one export.generate job each.
	type row struct {
		Format    string
		Priority  string
		Status    string
		CreatedBy string
	}
	read := func(id string) row {
		t.Helper()
		var r row
		if err := pool.QueryRow(ctx,
			`SELECT format, coalesce(filter->>'priority',''), status, created_by FROM exports WHERE id = $1`, id).
			Scan(&r.Format, &r.Priority, &r.Status, &r.CreatedBy); err != nil {
			t.Fatalf("read export %s: %v", id, err)
		}
		return r
	}
	apiRow, cliRow := read(apiID), read(cliResult.ID)
	if apiRow.Format != "csv" || apiRow.Priority != "P1" || apiRow.Status != "pending" {
		t.Fatalf("API export row = %+v, want csv/P1/pending", apiRow)
	}
	if cliRow.Format != apiRow.Format || cliRow.Priority != apiRow.Priority || cliRow.Status != apiRow.Status {
		t.Fatalf("CLI export row %+v != API %+v", cliRow, apiRow)
	}
	if apiRow.CreatedBy == "" || apiRow.CreatedBy != cliRow.CreatedBy {
		t.Fatalf("created_by differs: API %q, CLI %q (want the same resolved administrator)", apiRow.CreatedBy, cliRow.CreatedBy)
	}
	for _, id := range []string{apiID, cliResult.ID} {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM outbox WHERE type = 'export.generate' AND dedupe_key = $1`, "export.generate:"+id).Scan(&n); err != nil {
			t.Fatalf("count export.generate jobs for %s: %v", id, err)
		}
		if n != 1 {
			t.Fatalf("export %s enqueued %d export.generate jobs, want 1", id, n)
		}
	}
}

// TestI6RetentionChannelParity: the API dry-run and the CLI dry-run store the
// same counts-only report for the same due signal, and a non-Administrator is
// denied on both channels (403 / exit 4) without writing a run.
func TestI6RetentionChannelParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	if code, _, stderr := runCLI(t, env, "maintenance", "migrate"); code != exitOK {
		t.Fatalf("migrate exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)

	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	matchID := seedCreateSignalFixture(t, pool, base)
	i6SeedClosedSignal(t, pool, base, matchID)

	cfg := config.Defaults()
	svc := newAppService(&cfg, pool, clock.NewFakeClock(base))
	srv := newI6APIStack(t, svc, i6ParityBypassAdmin)

	// API dry-run.
	apiStatus, apiBody := i6PostJSON(t, srv.URL+"/api/v1/retention/runs", `{"stage":"delete"}`)
	if apiStatus != http.StatusOK {
		t.Fatalf("API retention status = %d, want 200 (%v)", apiStatus, apiBody)
	}
	apiID, _ := apiBody["id"].(string)
	if apiID == "" {
		t.Fatalf("API retention returned no id (%v)", apiBody)
	}

	// CLI dry-run.
	code, stdout, stderr := runCLI(t, env, "maintenance", "retention", "--dry-run", "--stage", "delete",
		"--as", i6ParityAdminSubject, "--output", "json")
	if code != exitOK {
		t.Fatalf("CLI retention exit = %d, want 0 (stderr: %s; stdout: %s)", code, stderr, stdout)
	}
	cliEnv := decodeEnvelope(t, stdout)
	var cliResult struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		DryRun *struct {
			Candidates int `json:"candidates"`
			Held       int `json:"held"`
			ToDelete   int `json:"to_delete"`
		} `json:"dry_run"`
	}
	if err := json.Unmarshal(cliEnv.Result, &cliResult); err != nil {
		t.Fatalf("decode CLI retention result: %v (%s)", err, string(cliEnv.Result))
	}
	if cliResult.ID == "" || cliResult.DryRun == nil {
		t.Fatalf("CLI retention returned no report (%s)", string(cliEnv.Result))
	}

	// Both reports converge: dry_run, one actionable candidate, delete stage.
	type report struct {
		Policy   string
		Stage    string
		Status   string
		Cand     int
		Held     int
		ToDelete int
	}
	read := func(id string) report {
		t.Helper()
		var r report
		if err := pool.QueryRow(ctx,
			`SELECT policy_id, stage, status,
			        coalesce((dry_run->>'candidates')::int, -1),
			        coalesce((dry_run->>'held')::int, -1),
			        coalesce((dry_run->>'to_delete')::int, -1)
			 FROM retention_runs WHERE id = $1`, id).
			Scan(&r.Policy, &r.Stage, &r.Status, &r.Cand, &r.Held, &r.ToDelete); err != nil {
			t.Fatalf("read retention run %s: %v", id, err)
		}
		return r
	}
	apiRun, cliRun := read(apiID), read(cliResult.ID)
	if apiRun.Stage != "delete" || apiRun.Status != "dry_run" || apiRun.Cand != 1 || apiRun.Held != 0 || apiRun.ToDelete != 1 {
		t.Fatalf("API retention run = %+v, want delete/dry_run/1/0/1", apiRun)
	}
	if cliRun != apiRun {
		t.Fatalf("CLI retention run %+v != API %+v", cliRun, apiRun)
	}
	if cliResult.Status != "dry_run" || cliResult.DryRun.ToDelete != apiRun.ToDelete {
		t.Fatalf("CLI wire report = %+v, want dry_run with %d to_delete", cliResult, apiRun.ToDelete)
	}

	// Denied path parity: an analyst holds no retention.manage.
	analystSrv := newI6APIStack(t, svc, i6ParityBypassAnalyst)
	deniedStatus, _ := i6PostJSON(t, analystSrv.URL+"/api/v1/retention/runs", `{"stage":"delete"}`)
	if deniedStatus != http.StatusForbidden {
		t.Fatalf("API analyst retention status = %d, want 403", deniedStatus)
	}
	code, _, stderr = runCLI(t, env, "maintenance", "retention", "--dry-run", "--as", i6ParityAnalystSubject)
	if code != exitAuthorisation {
		t.Fatalf("CLI analyst retention exit = %d, want %d (stderr: %s)", code, exitAuthorisation, stderr)
	}
	// Both denials wrote no run (the two allowed runs above are the only rows).
	var runs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM retention_runs`).Scan(&runs); err != nil {
		t.Fatalf("count retention runs: %v", err)
	}
	if runs != 2 {
		t.Fatalf("retention runs = %d, want 2 (a denied dry-run writes nothing)", runs)
	}
}
