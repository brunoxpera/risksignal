package observability_test

// Integration test of the §16.2 gauge sampler (ARCH-007 §5/§16.2,
// WP-6.08/6.12 follow-up / DEV-138). It runs against a real, short-lived
// PostgreSQL database created per test case, migrated with the real migration
// set (db/migrations) and dropped afterwards. The database server is the
// compose `db` service (make up) or any PostgreSQL reachable through
// RISKSIGNAL_TEST_DATABASE_URL; the connecting user needs CREATEDB. When no
// database is reachable the test skips, so `go test ./...` stays green on
// machines without the environment.
//
// The test proves the DEV-120 coverage gap is closed: after one collection
// pass against a seeded database, every declared §16.2 gauge family the
// collector owns carries a real series (no declared-but-unwritten gauge), and
// the sampled values reflect the seeded state.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/observability"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// collectorTestDBURL points at the compose db service (compose.yaml).
const collectorTestDBURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// collectorMigrationDir locates the real migration set (db/migrations)
// relative to this test package's directory (go test runs the binary with
// cwd = the package dir). The adapters layer must not import db/migrations —
// only the composition roots may (go-arch-lint) — so the files are read from
// disk through os.DirFS.
const collectorMigrationDir = "../../../db/migrations"

// newCollectorTestPool creates a dedicated database, migrates it with the real
// migration set and returns a pool on it. The pool is closed before the
// database is dropped; the test skips when no PostgreSQL is reachable.
func newCollectorTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := os.Getenv("RISKSIGNAL_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = collectorTestDBURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Skipf("integration database unavailable: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Skipf("integration database not reachable (set RISKSIGNAL_TEST_DATABASE_URL): %v", err)
	}

	name := fmt.Sprintf("risksignal_gauge_%d", time.Now().UnixNano())
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

	runner, err := migrate.Open(context.Background(), dbURL, os.DirFS(collectorMigrationDir))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	mctx, mcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer mcancel()
	if _, err := runner.Migrate(mctx, false); err != nil {
		_ = runner.Close()
		t.Fatalf("migrate: %v", err)
	}
	_ = runner.Close()

	pool, err := postgres.OpenPool(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedGaugeScenario inserts one row of every kind a §16.2 gauge samples: a
// source with a succeeded run (a data-age basis), an open unassigned P1 signal
// with an open SLA clock, a pending notification and a due outbox job.
func seedGaugeScenario(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	var sourceID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO sources (type, name, enabled) VALUES ('nvd', 'gauge-seed', true) RETURNING id`).
		Scan(&sourceID); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	basis := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second).Format(time.RFC3339)
	if _, err := pool.Exec(ctx, `
		INSERT INTO source_runs (source_id, started_at, finished_at, status, counters, cursor_after)
		VALUES ($1, now() - interval '10 minutes', now() - interval '9 minutes', 'succeeded', '{}'::jsonb, $2::jsonb)`,
		sourceID, `{"last_modified":"`+basis+`"}`); err != nil {
		t.Fatalf("seed source run: %v", err)
	}

	var matchID string
	if err := pool.QueryRow(ctx, `
		WITH a AS (
		    INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure)
		    VALUES ('gauge-srv-1', 'seed', 'server', 'gauge-srv-1', 'prod', 'critical', 'internet')
		    RETURNING id
		), c AS (
		    INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, natural_key, version_scheme)
		    SELECT id, 'acme', 'widget', '1.0', 'acme', 'widget', 'cpe:acme:widget:1.0', 'generic' FROM a
		    RETURNING id
		), v AS (
		    INSERT INTO vulnerabilities (cve_id, summary, published_at)
		    VALUES ('CVE-2026-1380', 'gauge seed vuln', now())
		    RETURNING id
		), m AS (
		    INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
		    SELECT v.id, c.id, 'exact_version', 100, 'high', 'i1b-1', now() FROM v, c
		    RETURNING id
		)
		SELECT id FROM m`).Scan(&matchID); err != nil {
		t.Fatalf("seed inventory/match chain: %v", err)
	}

	var signalID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO risk_signals (match_id, priority, status, owner, rule_version, factors, created_at)
		VALUES ($1, 'P1', 'new', NULL, 'p0000000001', '{}'::jsonb, now())
		RETURNING id`, matchID).Scan(&signalID); err != nil {
		t.Fatalf("seed signal: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at)
		VALUES ($1, 'acknowledgement', now() - interval '1 minute', now() + interval '20 minutes')`,
		signalID); err != nil {
		t.Fatalf("seed sla clock: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO notifications (signal_id, channel, kind, status, outbox_event_id, created_at)
		VALUES ($1, 'in_app', 'signal.created', 'pending', 'gauge-event-1', now() - interval '3 minutes')`,
		signalID); err != nil {
		t.Fatalf("seed notification: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO outbox (type, payload, status, available_at, dedupe_key, created_at)
		VALUES ('signal.created', '{}'::jsonb, 'pending', now() - interval '2 minutes', 'gauge-dedupe-1', now() - interval '2 minutes')`); err != nil {
		t.Fatalf("seed outbox job: %v", err)
	}
}

// TestI6ExitCriteriaGaugeFamiliesPopulated is the NFR-010 acceptance case for
// the DEV-138 gap: one collection pass against a seeded database populates
// every declared §16.2 gauge family the collector owns, and the sampled values
// match the seeded state.
func TestI6ExitCriteriaGaugeFamiliesPopulated(t *testing.T) {
	pool := newCollectorTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedGaugeScenario(t, ctx, pool)

	reg := metrics.New()
	metrics.RegisterStandard(reg)
	collector := observability.NewCollector(pool, reg, nil)
	if err := collector.Collect(ctx); err != nil {
		t.Fatalf("collect: %v", err)
	}

	byName := map[string][]metrics.Sample{}
	for _, s := range reg.Snapshot() {
		byName[s.Name] = append(byName[s.Name], s)
	}
	for _, name := range observability.GaugeFamilies() {
		if len(byName[name]) == 0 {
			t.Errorf("gauge family %q is declared but carries no series after collection (declared-but-unwritten)", name)
		}
	}

	// The sampled values reflect the seeded state — presence alone would not
	// prove the wiring reads the right source.
	if v := gaugeValue(t, byName, metrics.NameSignalsUnassigned, ""); v != 1 {
		t.Errorf("signals_unassigned = %v, want 1", v)
	}
	if v := gaugeValue(t, byName, metrics.NameSignalsOpenByPriority, "P1"); v != 1 {
		t.Errorf("signals_open_by_priority{P1} = %v, want 1", v)
	}
	if v := gaugeValue(t, byName, metrics.NameSignalsOpenByPriority, "P4"); v != 0 {
		t.Errorf("signals_open_by_priority{P4} = %v, want 0 (emitted for every priority)", v)
	}
	if v := gaugeValue(t, byName, metrics.NameDatabaseSizeBytes, ""); v <= 0 {
		t.Errorf("database_size_bytes = %v, want > 0", v)
	}
	if v := gaugeValue(t, byName, metrics.NameDatabaseConnections, ""); v < 1 {
		t.Errorf("database_connections = %v, want >= 1", v)
	}
	if v := gaugeValue(t, byName, metrics.NameJobsOldestAge, ""); v < 100 {
		t.Errorf("jobs_oldest_age_seconds = %v, want >= ~120s (the due job is 2 minutes old)", v)
	}
	if v := gaugeValue(t, byName, metrics.NameNotificationsRetryAge, ""); v < 150 {
		t.Errorf("notifications_retry_age_seconds = %v, want >= ~180s (the pending notification is 3 minutes old)", v)
	}
	if v := gaugeValue(t, byName, metrics.NameSourceDataAge, "nvd"); v < 250 {
		t.Errorf("source_data_age_seconds = %v, want >= ~300s (the cursor basis is 5 minutes old)", v)
	}
}

// gaugeValue returns the value of the series of a family carrying label=value
// (label == "" matches the unlabeled series).
func gaugeValue(t *testing.T, byName map[string][]metrics.Sample, name, label string) float64 {
	t.Helper()
	for _, s := range byName[name] {
		if label == "" {
			if len(s.Labels) == 0 {
				return s.Value
			}
			continue
		}
		// The labelled families use a single identifying label whose value is
		// the priority or the source name; match on any label holding it.
		for _, v := range s.Labels {
			if v == label {
				return s.Value
			}
		}
	}
	t.Fatalf("no series of %q with a label value %q: %+v", name, label, byName[name])
	return 0
}
