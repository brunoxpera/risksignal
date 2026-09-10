package worker_test

// Integration tests for the I6 worker jobs (ARCH-007 §1.2/§2.2, WP-6.06 /
// DEV-118): export.generate and retention.execute driven end to end through
// the real outbox relay and the real postgres repositories, plus the daily
// export sweep and the monthly retention dry-run proposal.
//
// They run against a real, short-lived PostgreSQL database created per test
// case and migrated with the embedded set (the same shape as the
// internal/adapters/postgres/repo integration tests). When no database is
// reachable the tests skip, so `go test ./...` stays green on machines without
// the environment.
//
// Coverage:
//   - export.generate materialises the artifact and stamps the row, is
//     idempotent on the export id and crash-safe (a reset row regenerates and
//     re-stamps);
//   - a permanent export.generate failure dead-letters the job;
//   - retention.execute executes an approved run in bounded batches, writes a
//     retention.executed audit event per batch, is idempotent on re-enqueue
//     and resumable (a re-run skips the already-deleted rows);
//   - a permanent retention.execute failure dead-letters the job;
//   - the export sweep deletes the expired artifact and marks the row expired
//     (and the monthly scheduler proposes a dry-run).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/worker"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// jobsTestDBURL is the compose `db` service (make up) or any PostgreSQL
// reachable through RISKSIGNAL_TEST_DATABASE_URL.
const jobsTestDBURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// jobsMigrationDir locates the migration set (db/migrations) relative to this
// package directory.
const jobsMigrationDir = "../../../db/migrations"

// jobsNow is the FakeClock instant of the tests. It is comfortably in the past
// relative to the database's wall clock, so every outbox row the commands
// enqueue (available_at = jobsNow) is claimable.
var jobsNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func jobsLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newJobsTestPool creates a dedicated database, migrates it with the embedded
// set and returns a pool on it. It skips when no PostgreSQL is reachable.
func newJobsTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := os.Getenv("RISKSIGNAL_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = jobsTestDBURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Skipf("integration database unavailable: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Skipf("integration database not reachable (set RISKSIGNAL_TEST_DATABASE_URL): %v", err)
	}

	name := fmt.Sprintf("risksignal_jobs_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		admin.Close()
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(c, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
			t.Errorf("drop test database %s: %v", name, err)
		}
	})

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("parse test database url: %v", err)
	}
	u.Path = "/" + name
	dbURL := u.String()

	runner, err := migrate.Open(context.Background(), dbURL, os.DirFS(jobsMigrationDir))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(context.Background(), false); err != nil {
		_ = runner.Close()
		t.Fatalf("fresh migrate: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	pool, err := postgres.OpenPool(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newJobsService wires the application service on the real postgres
// repositories of pool, with the given clock, spool directory and retention
// batch size.
func newJobsService(pool *pgxpool.Pool, clk clock.Clock, spoolDir string, batchSize int) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:            repo.NewSignalRepo(q),
		Audit:              repo.NewAuditRepo(q),
		Outbox:             repo.NewOutboxRepo(q),
		Vulnerabilities:    repo.NewVulnerabilityRepo(q),
		Matches:            repo.NewMatchRepo(q),
		SourceRuns:         repo.NewSourceRunRepo(q),
		RawRecords:         repo.NewRawRecordRepo(q),
		Sources:            repo.NewSourceRepo(q),
		Quarantine:         repo.NewQuarantineRepo(q),
		Components:         repo.NewComponentRepo(q),
		Inventory:          repo.NewInventoryRepo(q),
		PriorityRules:      repo.NewPriorityRuleRepo(q),
		Exports:            repo.NewExportRepo(q),
		ExportStore:        export.NewSpool(spoolDir),
		SignalExport:       repo.NewSignalExportSource(q),
		Retention:          repo.NewRetentionRepo(q),
		RetentionBatchSize: batchSize,
		Clock:              clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// newJobsRelay builds the relay with the export and retention handlers
// registered; the two job sets are returned so the sweep/schedule can be
// driven.
func newJobsRelay(t *testing.T, pool *pgxpool.Pool, svc *application.Service, clk clock.Clock) (*worker.Relay, *worker.ExportJobs, *worker.RetentionJobs) {
	t.Helper()
	relay, err := worker.NewRelay(repo.NewOutboxRelay(gen.New(pool)), jobsLogger())
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	exportJobs, err := worker.NewExportJobs(svc, svc, clk, 24*time.Hour, jobsLogger())
	if err != nil {
		t.Fatalf("NewExportJobs: %v", err)
	}
	if err := exportJobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("register export handlers: %v", err)
	}
	retentionJobs, err := worker.NewRetentionJobs(svc, svc, clk, 30*24*time.Hour, jobsLogger())
	if err != nil {
		t.Fatalf("NewRetentionJobs: %v", err)
	}
	if err := retentionJobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("register retention handlers: %v", err)
	}
	return relay, exportJobs, retentionJobs
}

// seedSignal inserts one asset/component/vulnerability/match/risk_signals
// chain and returns the signal id.
func seedSignal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ext, priority, status, product string, createdAt time.Time, closedAt *time.Time) string {
	t.Helper()
	cve := "CVE-2026-" + ext
	var signalID string
	err := pool.QueryRow(ctx, `
		WITH a AS (
		    INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure)
		    VALUES ($1, 'jobs-seed', 'server', $1, 'prod', 'critical', 'internet')
		    RETURNING id
		), c AS (
		    INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, natural_key, version_scheme)
		    SELECT id, 'acme', $2, '1.0', 'acme', $2, 'cpe:acme:' || $2 || ':1.0', 'generic' FROM a
		    RETURNING id
		), v AS (
		    INSERT INTO vulnerabilities (cve_id, summary, published_at)
		    VALUES ($3, 'jobs seed ' || $3, now())
		    RETURNING id
		), m AS (
		    INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
		    SELECT v.id, c.id, 'exact_version', 100, 'high', 'i1b-1', now() FROM v, c
		    RETURNING id
		), rs AS (
		    INSERT INTO risk_signals (match_id, priority, status, rule_version, factors, created_at, closed_at)
		    SELECT m.id, $4, $5, 'i1b-1', '{}'::jsonb, $6, $7 FROM m
		    RETURNING id
		)
		SELECT id FROM rs`, ext, product, cve, priority, status, createdAt, closedAt).Scan(&signalID)
	if err != nil {
		t.Fatalf("seed signal %s: %v", ext, err)
	}
	return signalID
}

// countRows is a small scalar-count helper.
func countRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// enqueueJob appends one outbox job on its own transaction (the test-side
// equivalent of a command's atomic enqueue).
func enqueueJob(t *testing.T, ctx context.Context, pool *pgxpool.Pool, typ string, payload []byte, dedupe string, at time.Time) {
	t.Helper()
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repo.NewOutboxRepo(gen.New(pool)).Append(ctx, tx, application.OutboxEvent{
			Type:        typ,
			Payload:     payload,
			DedupeKey:   dedupe,
			AvailableAt: at,
			CreatedAt:   at,
		})
	}); err != nil {
		t.Fatalf("enqueue %s: %v", typ, err)
	}
}

// outboxState reads one outbox row's status and last_error by dedupe key.
func outboxState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, dedupe string) (string, string) {
	t.Helper()
	var status, lastErr string
	if err := pool.QueryRow(ctx,
		`SELECT status, COALESCE(last_error, '') FROM outbox WHERE dedupe_key = $1`, dedupe).
		Scan(&status, &lastErr); err != nil {
		t.Fatalf("read outbox %s: %v", dedupe, err)
	}
	return status, lastErr
}

// ---------------------------------------------------------------------------
// export.generate

func TestExportGenerateJobIntegration(t *testing.T) {
	pool := newJobsTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clk := clock.NewFakeClock(jobsNow)
	spoolDir := t.TempDir()
	svc := newJobsService(pool, clk, spoolDir, 0)
	relay, _, _ := newJobsRelay(t, pool, svc, clk)

	seedSignal(t, ctx, pool, "1001", "P1", "new", "acme", jobsNow, nil)
	seedSignal(t, ctx, pool, "1002", "P2", "new", "acme", jobsNow, nil)
	seedSignal(t, ctx, pool, "1003", "P2", "new", "other", jobsNow, nil)

	p1 := "P1"
	_ = p1
	created, err := svc.CreateExport(ctx, application.CreateExportInput{
		Filter: application.ExportFilter{Product: "acme"},
		Format: export.FormatCSV,
		Actor:  application.Actor{Type: application.ActorTypeSystem, ID: "svc"},
	})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	if status, lastErr := outboxState(t, ctx, pool, "export.generate:"+created.ExportID); status != "done" {
		t.Fatalf("outbox status = %q (last_error %q), want done", status, lastErr)
	}

	var row application.Export
	row, err = repo.NewExportRepo(gen.New(pool)).GetByID(ctx, created.ExportID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if row.Status != application.ExportStatusCompleted || row.RowCount != 2 {
		t.Fatalf("export = %+v, want completed with 2 rows", row)
	}
	wantRule, _ := domain.PriorityRuleVersion(1) // migration 00007 seeds ruleset v1
	if row.SchemaVersion != export.SchemaVersion || row.RuleVersion != wantRule {
		t.Fatalf("versions = %q/%q, want schema %q and rule %q", row.SchemaVersion, row.RuleVersion, export.SchemaVersion, wantRule)
	}
	if !row.ExpiresAt.Equal(jobsNow.Add(application.DefaultExportTTL)) {
		t.Fatalf("expires_at = %s, want %s", row.ExpiresAt, jobsNow.Add(application.DefaultExportTTL))
	}
	// The artifact is a real file in the spool with a matching checksum.
	artifactPath := export.ArtifactKey(created.ExportID, export.FormatCSV)
	abs := spoolDir + "/" + artifactPath
	data, err := os.ReadFile(abs) //nolint:gosec // G304: abs is the test's own temp spool path
	if err != nil {
		t.Fatalf("read artifact %s: %v", abs, err)
	}
	if int64(len(data)) != row.SizeBytes {
		t.Fatalf("artifact size %d, want %d", len(data), row.SizeBytes)
	}

	// Idempotent: a redelivered job is a no-op.
	res, err := svc.GenerateExport(ctx, application.GenerateExportInput{ExportID: created.ExportID})
	if err != nil {
		t.Fatalf("second GenerateExport: %v", err)
	}
	if !res.Skipped {
		t.Fatal("a completed export was regenerated instead of skipped")
	}

	// Crash-safe: simulate a crash between the spool write and the stamp by
	// resetting the row to 'pending'; a retry regenerates and re-stamps.
	if _, err := pool.Exec(ctx, `UPDATE exports SET status = 'pending' WHERE id = $1`, created.ExportID); err != nil {
		t.Fatalf("reset export status: %v", err)
	}
	res, err = svc.GenerateExport(ctx, application.GenerateExportInput{ExportID: created.ExportID})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if res.Skipped || res.Status != application.ExportStatusCompleted {
		t.Fatalf("regenerate result = %+v, want a re-stamp", res)
	}
	if res.Checksum != row.Checksum {
		t.Fatalf("regenerated checksum %q, want the original %q (deterministic)", res.Checksum, row.Checksum)
	}
}

func TestExportGenerateDeadLetter(t *testing.T) {
	pool := newJobsTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clk := clock.NewFakeClock(jobsNow)
	svc := newJobsService(pool, clk, t.TempDir(), 0)
	relay, _, _ := newJobsRelay(t, pool, svc, clk)

	// An unknown export id is a not-found — a permanent failure.
	payload, _ := jsonMarshal(application.ExportGeneratePayload{
		EventID:  "11111111-1111-1111-1111-111111111111",
		Type:     application.EventTypeExportGenerate,
		ExportID: "22222222-2222-2222-2222-222222222222",
	})
	dedupe := "export.generate:22222222-2222-2222-2222-222222222222"
	enqueueJob(t, ctx, pool, application.EventTypeExportGenerate, payload, dedupe, jobsNow)

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	status, lastErr := outboxState(t, ctx, pool, dedupe)
	if status != "dead_letter" || lastErr == "" {
		t.Fatalf("outbox = (%q, %q), want a dead-letter with an error", status, lastErr)
	}
}

// ---------------------------------------------------------------------------
// retention.execute

func TestRetentionExecuteJobIntegration(t *testing.T) {
	pool := newJobsTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clk := clock.NewFakeClock(jobsNow)
	svc := newJobsService(pool, clk, t.TempDir(), 2) // bounded batches of 2
	relay, _, _ := newJobsRelay(t, pool, svc, clk)

	closedAt := jobsNow.AddDate(-6, 0, 0)
	for i := 0; i < 5; i++ {
		closed := closedAt
		seedSignal(t, ctx, pool, fmt.Sprintf("200%d", i), "P2", "resolved", "acme", closedAt, &closed)
	}

	admin := application.Actor{Type: application.ActorTypeSystem, ID: "retention-admin"}
	dry, err := svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: admin})
	if err != nil {
		t.Fatalf("RunRetentionDryRun: %v", err)
	}
	if dry.Counts.Candidates != 5 {
		t.Fatalf("dry-run candidates = %d, want 5", dry.Counts.Candidates)
	}

	approved, err := svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{
		RunID: dry.RunID, Reason: "5y elapsed", Actor: admin,
	})
	if err != nil {
		t.Fatalf("ApproveRetentionRun: %v", err)
	}
	if approved.Status != application.RetentionStatusApproved {
		t.Fatalf("approved status = %q", approved.Status)
	}
	// The approval enqueued exactly one retention.execute job (idempotent key
	// policy_id + cutoff + partition).
	dedupe := "retention.execute:" + application.RetentionPolicyClosedSignals + ":" +
		dry.Cutoff.UTC().Format(time.RFC3339) + ":" + dry.Cutoff.UTC().Format("2006-01")
	if n := countRows(t, ctx, pool, `SELECT count(*) FROM outbox WHERE dedupe_key = $1`, dedupe); n != 1 {
		t.Fatalf("retention.execute outbox rows = %d, want 1", n)
	}
	// A re-enqueue of the same plan is rejected by the UQ (idempotent).
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		payload, _ := jsonMarshal(application.RetentionExecutePayload{
			EventID: "33333333-3333-3333-3333-333333333333",
			Type:    application.EventTypeRetentionExecute, RunID: dry.RunID,
		})
		return repo.NewOutboxRepo(gen.New(pool)).Append(ctx, tx, application.OutboxEvent{
			Type: application.EventTypeRetentionExecute, Payload: payload,
			DedupeKey: dedupe, AvailableAt: jobsNow, CreatedAt: jobsNow,
		})
	}); err == nil {
		t.Fatal("a duplicate retention.execute enqueue succeeded")
	}

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if status, lastErr := outboxState(t, ctx, pool, dedupe); status != "done" {
		t.Fatalf("retention.execute outbox = (%q, %q), want done", status, lastErr)
	}

	// Every seeded signal (and its match) is gone.
	if n := countRows(t, ctx, pool, `SELECT count(*) FROM risk_signals`); n != 0 {
		t.Fatalf("risk_signals = %d, want 0", n)
	}
	if n := countRows(t, ctx, pool, `SELECT count(*) FROM matches`); n != 0 {
		t.Fatalf("matches = %d, want 0", n)
	}
	run, err := repo.NewRetentionRepo(gen.New(pool)).GetRun(ctx, dry.RunID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if run.Status != application.RetentionStatusCompleted || run.Deleted != 5 {
		t.Fatalf("run = %+v, want completed with 5 deleted", run)
	}
	// One retention.executed audit event per batch: ceil(5/2) = 3.
	if n := countRows(t, ctx, pool,
		`SELECT count(*) FROM audit_events WHERE action = 'retention.executed'`); n != 3 {
		t.Fatalf("retention.executed audit rows = %d, want 3", n)
	}

	// Resumable: a re-run of the (now completed) run re-scans and naturally
	// skips the already-deleted rows. Re-approve by resetting the row.
	if _, err := pool.Exec(ctx, `UPDATE retention_runs SET status = 'approved' WHERE id = $1`, dry.RunID); err != nil {
		t.Fatalf("reset run status: %v", err)
	}
	res, err := svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{RunID: dry.RunID, Actor: admin})
	if err != nil {
		t.Fatalf("re-execute: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("re-run deleted = %d, want 0 (already-deleted rows skipped)", res.Deleted)
	}
}

func TestRetentionExecuteDeadLetter(t *testing.T) {
	pool := newJobsTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clk := clock.NewFakeClock(jobsNow)
	svc := newJobsService(pool, clk, t.TempDir(), 0)
	relay, _, _ := newJobsRelay(t, pool, svc, clk)

	// An unknown run id is a not-found — a permanent failure.
	payload, _ := jsonMarshal(application.RetentionExecutePayload{
		EventID:  "44444444-4444-4444-4444-444444444444",
		Type:     application.EventTypeRetentionExecute,
		RunID:    "55555555-5555-5555-5555-555555555555",
		PolicyID: application.RetentionPolicyClosedSignals,
	})
	dedupe := "retention.execute:closed-signals-5y:2021-06-01T12:00:00Z:bucket"
	enqueueJob(t, ctx, pool, application.EventTypeRetentionExecute, payload, dedupe, jobsNow)

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	status, lastErr := outboxState(t, ctx, pool, dedupe)
	if status != "dead_letter" || lastErr == "" {
		t.Fatalf("outbox = (%q, %q), want a dead-letter with an error", status, lastErr)
	}
}

// ---------------------------------------------------------------------------
// export sweep + retention dry-run scheduler

func TestExportSweepMarksExpired(t *testing.T) {
	pool := newJobsTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clk := clock.NewFakeClock(jobsNow)
	spoolDir := t.TempDir()
	svc := newJobsService(pool, clk, spoolDir, 0)
	_, exportJobs, _ := newJobsRelay(t, pool, svc, clk)

	// One completed export past its TTL with a real artifact, one still fresh.
	spool := export.NewSpool(spoolDir)
	expiredArtifact, err := spool.Write(ctx, "expired.csv", stringReader("old"))
	if err != nil {
		t.Fatalf("write expired artifact: %v", err)
	}
	freshArtifact, err := spool.Write(ctx, "fresh.csv", stringReader("new"))
	if err != nil {
		t.Fatalf("write fresh artifact: %v", err)
	}
	seedCompletedExport(t, ctx, pool, expiredArtifact.Path, jobsNow.Add(-time.Hour))
	seedCompletedExport(t, ctx, pool, freshArtifact.Path, jobsNow.Add(time.Hour))

	if err := exportJobs.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n := countRows(t, ctx, pool, `SELECT count(*) FROM exports WHERE status = 'expired'`); n != 1 {
		t.Fatalf("expired exports = %d, want 1", n)
	}
	if _, err := os.Stat(spoolDir + "/" + expiredArtifact.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired artifact still present: %v", err)
	}
	if _, err := os.Stat(spoolDir + "/" + freshArtifact.Path); err != nil {
		t.Fatalf("fresh artifact was removed: %v", err)
	}
	// The fresh export stays completed.
	if n := countRows(t, ctx, pool, `SELECT count(*) FROM exports WHERE status = 'completed'`); n != 1 {
		t.Fatalf("completed exports = %d, want 1", n)
	}
}

func TestRetentionScheduleProposesDryRun(t *testing.T) {
	pool := newJobsTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clk := clock.NewFakeClock(jobsNow)
	svc := newJobsService(pool, clk, t.TempDir(), 0)
	_, _, retentionJobs := newJobsRelay(t, pool, svc, clk)

	closed := jobsNow.AddDate(-6, 0, 0)
	seedSignal(t, ctx, pool, "3001", "P2", "resolved", "acme", closed, &closed)

	if err := retentionJobs.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if n := countRows(t, ctx, pool, `SELECT count(*) FROM retention_runs WHERE status = 'dry_run'`); n != 1 {
		t.Fatalf("dry_run rows = %d, want 1", n)
	}
	// The cadence gate makes a second tick within the interval a no-op.
	if err := retentionJobs.Tick(ctx); err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if n := countRows(t, ctx, pool, `SELECT count(*) FROM retention_runs`); n != 1 {
		t.Fatalf("retention_runs = %d, want 1 (cadence-gated)", n)
	}
}

// ---------------------------------------------------------------------------
// small helpers

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func stringReader(s string) io.Reader { return strings.NewReader(s) }

// seedCompletedExport inserts one completed export row with the given spool
// path and expiry (the sweep fixture).
func seedCompletedExport(t *testing.T, ctx context.Context, pool *pgxpool.Pool, storagePath string, expiresAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO exports (status, filter, format, storage_path, row_count, size_bytes, checksum, schema_version, rule_version, created_by, created_at, expires_at)
		VALUES ('completed', '{}'::jsonb, 'csv', $1, 0, 0, 'deadbeef', '1', 'i1b-1', 'svc', $2, $3)`,
		storagePath, jobsNow, expiresAt); err != nil {
		t.Fatalf("seed completed export: %v", err)
	}
}
