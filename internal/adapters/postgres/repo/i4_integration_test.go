package repo

// Integration test for the I4 persistence paths (WP-4.03 / DEV-073): the
// priority-rules snapshot publish + effective read, the guarded signal
// transition (optimistic lock — a stale version is a conflict), the SLA
// clock upsert + idempotent fulfil, and the idempotent notification insert.
//
// It runs against a real, short-lived PostgreSQL database created per test
// case, migrated with the embedded migration set (db/migrations) and dropped
// afterwards. The database server is the compose `db` service (make up) or
// any PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; the
// connecting user needs CREATEDB. When no database is reachable the test
// skips, so `go test ./...` stays green on machines without the environment.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// i4TestDBURL points at the compose db service (compose.yaml, WP-1a.03).
const i4TestDBURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// i4MigrationDir locates the embedded migration set (db/migrations) relative
// to this test package's directory (go test runs the binary with cwd = the
// package dir). The adapters layer must not import db/migrations — only the
// composition roots (cmd) may (go-arch-lint) — so the files are read from
// disk through os.DirFS rather than the embedded FS.
const i4MigrationDir = "../../../../db/migrations"

// newI4TestPool creates a dedicated database, migrates it with the embedded
// set and returns a pool on it. The pool is closed before the database is
// dropped; the test skips when no PostgreSQL is reachable.
func newI4TestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := os.Getenv("RISKSIGNAL_TEST_DATABASE_URL")
	if adminURL == "" {
		adminURL = i4TestDBURL
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

	name := fmt.Sprintf("risksignal_i4_%d", time.Now().UnixNano())
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

	runner, err := migrate.Open(context.Background(), dbURL, os.DirFS(i4MigrationDir))
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

// seedSignal inserts the minimal inventory/match chain one signal needs and
// returns the signal id.
func seedSignal(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var matchID string
	err := pool.QueryRow(ctx, `
		WITH a AS (
		    INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure)
		    VALUES ('i4-srv-1', 'seed', 'server', 'i4-srv-1', 'prod', 'critical', 'internet')
		    RETURNING id
		), c AS (
		    INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, natural_key, version_scheme)
		    SELECT id, 'acme', 'widget', '1.0', 'acme', 'widget', 'cpe:acme:widget:1.0', 'generic' FROM a
		    RETURNING id
		), v AS (
		    INSERT INTO vulnerabilities (cve_id, summary, published_at)
		    VALUES ('CVE-2026-0730', 'i4 seed vuln', now())
		    RETURNING id
		), m AS (
		    INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
		    SELECT v.id, c.id, 'exact_version', 100, 'high', 'i1b-1', now() FROM v, c
		    RETURNING id
		)
		SELECT id FROM m`).Scan(&matchID)
	if err != nil {
		t.Fatalf("seed inventory/match chain: %v", err)
	}

	var signalID string
	err = pool.QueryRow(ctx, `
		INSERT INTO risk_signals (match_id, priority, rule_version, factors, created_at)
		VALUES ($1, 'P1', 'p0000000001',
		        '{"method":"exact_version","confidence":"high","kev":true,"cvss":9.9,"epss":0.9,"criticality":"critical","exposure":"internet"}'::jsonb,
		        now())
		RETURNING id`, matchID).Scan(&signalID)
	if err != nil {
		t.Fatalf("seed signal: %v", err)
	}
	return signalID
}

// TestI4PersistenceIntegration exercises the four I4 persistence paths
// against a real database (the DEV-073 acceptance criterion).
func TestI4PersistenceIntegration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := gen.New(pool)

	signalID := seedSignal(t, ctx, pool)
	now := time.Now().UTC().Truncate(time.Millisecond)

	// 1. priority_rules: the migration seeded ruleset v1; a publish writes
	// snapshot v2 and the effective read returns it.
	rulesRepo := NewPriorityRuleRepo(q)
	if v, err := rulesRepo.EffectiveVersion(ctx); err != nil || v != 1 {
		t.Fatalf("effective version before publish = %d (err %v), want 1", v, err)
	}
	rules := domain.SeedPriorityRules()
	var published int
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		published, err = rulesRepo.Publish(ctx, tx, rules, now, "integration test", "tester", now)
		return err
	}); err != nil {
		t.Fatalf("publish ruleset: %v", err)
	}
	if published != 2 {
		t.Fatalf("published version = %d, want 2", published)
	}
	if v, err := rulesRepo.EffectiveVersion(ctx); err != nil || v != 2 {
		t.Fatalf("effective version after publish = %d (err %v), want 2", v, err)
	}
	effective, err := rulesRepo.Effective(ctx)
	if err != nil {
		t.Fatalf("effective rules: %v", err)
	}
	if len(effective) != 4 {
		t.Fatalf("effective rules = %d, want 4", len(effective))
	}
	for i, r := range effective {
		want := domain.Priority(fmt.Sprintf("P%d", i+1))
		if r.RuleID != want || r.Version != 2 || !r.Enabled {
			t.Fatalf("effective rule %d = %+v, want rule_id %s version 2 enabled", i, r, want)
		}
	}

	// 2. risk_signals: a guarded transition bumps the version; a stale
	// expected version is a conflict.
	signalRepo := NewSignalRepo(q)
	sig, err := signalRepo.GetRiskSignal(ctx, signalID)
	if err != nil {
		t.Fatalf("get signal: %v", err)
	}
	if sig.Version != 1 || sig.Status != domain.SignalStatusNew {
		t.Fatalf("seeded signal = %+v, want version 1 status new", sig)
	}
	var transitioned domain.RiskSignal
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		transitioned, err = signalRepo.Transition(ctx, tx, signalID, domain.SignalStatusInReview, nil, sig.Version)
		return err
	}); err != nil {
		t.Fatalf("transition: %v", err)
	}
	if transitioned.Status != domain.SignalStatusInReview || transitioned.Version != 2 {
		t.Fatalf("transitioned signal = %+v, want status in_review version 2", transitioned)
	}
	err = postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, err := signalRepo.Transition(ctx, tx, signalID, domain.SignalStatusActionPlanned, nil, sig.Version)
		return err
	})
	if err == nil {
		t.Fatal("stale transition succeeded, want a conflict")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("stale transition error kind = %s, want conflict", kind)
	}

	// 3. sla_clocks: upsert a clock, then fulfil it idempotently.
	clockRepo := NewSlaClockRepo(q)
	clock := domain.SlaClock{
		SignalID:   signalID,
		Target:     domain.SLATargetAcknowledgement,
		StartedAt:  now,
		DeadlineAt: now.Add(15 * time.Minute),
	}
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		stored, err := clockRepo.Upsert(ctx, tx, clock)
		if err != nil {
			return err
		}
		if stored.ID == "" || stored.Target != domain.SLATargetAcknowledgement {
			return fmt.Errorf("upserted clock = %+v", stored)
		}
		return nil
	}); err != nil {
		t.Fatalf("upsert clock: %v", err)
	}
	fulfilledAt := now.Add(5 * time.Minute)
	var firstChanged bool
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, changed, err := clockRepo.Fulfil(ctx, tx, signalID, domain.SLATargetAcknowledgement, fulfilledAt)
		firstChanged = changed
		return err
	}); err != nil {
		t.Fatalf("fulfil clock: %v", err)
	}
	if !firstChanged {
		t.Fatal("first fulfil reported unchanged, want changed")
	}
	var secondChanged bool
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, changed, err := clockRepo.Fulfil(ctx, tx, signalID, domain.SLATargetAcknowledgement, fulfilledAt.Add(time.Minute))
		secondChanged = changed
		return err
	}); err != nil {
		t.Fatalf("re-fulfil clock: %v", err)
	}
	if secondChanged {
		t.Fatal("second fulfil reported changed, want idempotent no-op")
	}

	// 4. notifications: the insert is idempotent on (outbox_event_id, channel).
	notifyRepo := NewNotificationRepo(q)
	var firstInserted bool
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, inserted, err := notifyRepo.Insert(ctx, tx, signalID, "in_app", "signal.created", "", "pending", "evt-0730", now)
		firstInserted = inserted
		return err
	}); err != nil {
		t.Fatalf("insert notification: %v", err)
	}
	if !firstInserted {
		t.Fatal("first notification insert reported not-inserted")
	}
	var secondInserted bool
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, inserted, err := notifyRepo.Insert(ctx, tx, signalID, "in_app", "signal.created", "", "pending", "evt-0730", now)
		secondInserted = inserted
		return err
	}); err != nil {
		t.Fatalf("re-insert notification: %v", err)
	}
	if secondInserted {
		t.Fatal("second notification insert reported inserted, want idempotent no-op")
	}
	list, err := notifyRepo.ListBySignal(ctx, signalID)
	if err != nil {
		t.Fatalf("list notifications: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("notifications = %d, want exactly 1 (idempotency key)", len(list))
	}
}
