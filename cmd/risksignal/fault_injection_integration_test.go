package main

// Integration test of the WP-1b.10 fault-injection atomicity gate (DEV-024,
// ARCH-001 §5) at the composition root. cmd/risksignal is the composition
// root that may wire the embedded migration set (db/migrations) together
// with the postgres adapter and the application service behind the real
// repositories (the architecture gate keeps db/migrations out of
// internal/adapters/** — `make lint-arch` enforces that), so the CreateSignal
// command runs here against a real, short-lived PostgreSQL exactly as
// production wires it (demo.go demoService): postgres.WithTx as the
// transaction boundary, the postgres repositories behind the ports, and the
// injected clock supplying every timestamp.
//
// The test proves the exit criterion of WP-1b.10 / the I1b exit criterion on
// real rows (TR-004, TAT-04):
//
//   (a) positive path — CreateSignal commits exactly one row each in
//       risk_signals, audit_events and outbox; the outbox row is pending
//       with dedupe_key "signal.created:<signal_id>" and the ARCH-001 §2
//       payload (event_id, type, signal_id, match_id, cve_id, priority,
//       occurred_at, correlation_id); the audit row carries the expected
//       action and the same correlation id; every timestamp comes back in
//       UTC (the DEV-023 pinUTCScan behaviour of postgres.NewPool);
//
//   (b) fault path — CreateSignal with a decorated OutboxRepo whose Append
//       fails after the signal and audit writes succeeded inside the same
//       transaction: the command returns the injected error and all three
//       tables stay empty. This is the literal "complete rollback" proof: a
//       fault between the domain change and the outbox write leaves nothing
//       behind.
//
// The fault is injected exactly on the ARCH-001 §5 seam: the decorator
// wraps the real postgres OutboxRepo (so every other port stays real) and
// overrides Append with a deterministic failpoint — an error return, no
// sleep, no flake. It lives in this test package, never in production code.
// The relay/at-least-once redelivery test is owned by WP-1b.06 (DEV-020) and
// deliberately not duplicated here.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// faultTestClockTime is the single point in time the injected FakeClock of
// the atomicity tests reads, so every assertion on created_at / occurred_at
// is exact and reproducible (ARCH-001 §3 reproducibility guarantee).
var faultTestClockTime = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)

// faultTestCorrelationID is the fixed correlation id of the test commands;
// it links the audit row and the outbox payload of one CreateSignal run
// (ARCH-001 §1 audit_events.correlation_id).
const faultTestCorrelationID = "corr-dev-024-1"

// faultTestCveID is the cve_id travelling into the outbox payload. The
// factors below derive to P1 (ch. 9.3), matching the C1 reference case of
// the demo matrix.
const faultTestCveID = "CVE-2024-0001"

// faultTestActorID is the system principal of the test commands (the same
// actor the synthetic source uses in production).
const faultTestActorID = "synthetic-source"

// newMigratedTestPool creates a dedicated scratch database (newTestDB),
// migrates it with the full embedded migration set and opens the pool under
// test on it. Tests skip when no PostgreSQL is reachable.
func newMigratedTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		_ = runner.Close()
		t.Fatalf("fresh migrate: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedCreateSignalFixture seeds the rows CreateSignal needs behind its
// foreign key: an asset, a component and a vulnerability linked by one
// method-led match (risk_signals.match_id -> matches.id, ARCH-001 §1). The
// match timestamp comes from the fixed test clock so the whole fixture is
// deterministic; it returns the canonical match id.
func seedCreateSignalFixture(t *testing.T, pool *pgxpool.Pool, at time.Time) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := gen.New(pool)

	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID:  "asset-portal",
		Source:      "demo",
		Type:        "server_vm",
		Name:        "Portal",
		Environment: "production",
		Criticality: "critical",
		Exposure:    "internet",
		Owner:       pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID: assetID, Vendor: "acme", Product: "portal", Version: "2.4",
	})
	if err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       faultTestCveID,
		Summary:     "Demo remote code execution",
		PublishedAt: mustTS(t, "2024-01-15T00:00:00Z"),
		ModifiedAt:  mustTS(t, "2026-09-01T00:00:00Z"),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}
	matchID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID,
		ComponentID:     componentID,
		Method:          "exact_identifier",
		Score:           100,
		Confidence:      "high",
		RuleVersion:     "i1b-1",
		CreatedAt:       mustTS(t, at.Format(time.RFC3339)),
	})
	if err != nil {
		t.Fatalf("InsertMatch: %v", err)
	}
	return demoUUID(matchID)
}

// newCreateSignalService wires the application service exactly as the
// production composition roots do (demo.go demoService): the postgres
// repositories behind the ports and postgres.WithTx as the transaction
// boundary of the command (ch. 5.1), with the injected FakeClock as the
// time source and the given outbox repository — the real one or the
// ARCH-001 §5 failing decorator.
func newCreateSignalService(pool *pgxpool.Pool, outbox application.OutboxRepo, clk clock.Clock) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          outbox,
		Vulnerabilities: repo.NewVulnerabilityRepo(q),
		Matches:         repo.NewMatchRepo(q),
		SourceRuns:      repo.NewSourceRunRepo(q),
		Components:      repo.NewComponentRepo(q),
		Clock:           clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// faultTestInput is the CreateSignal command of the atomicity tests: the
// P1 factor set (exact_identifier/high, KEV, critical + internet — ch. 9.3)
// and the fixed correlation id, so the assertions are exact.
func faultTestInput(matchID string) application.CreateSignalInput {
	return application.CreateSignalInput{
		MatchID: matchID,
		CveID:   faultTestCveID,
		Factors: domain.PriorityFactors{
			Method:      domain.MatchMethodExactIdentifier,
			Confidence:  domain.ConfidenceHigh,
			KEV:         true,
			CVSS:        9.8,
			EPSS:        0.99,
			Criticality: domain.CriticalityCritical,
			Exposure:    domain.ExposureInternet,
		},
		CorrelationID: faultTestCorrelationID,
		Actor:         application.Actor{Type: application.ActorTypeSystem, ID: faultTestActorID},
	}
}

// failingOutboxRepo is the ARCH-001 §5 fault injection. It decorates the
// real postgres OutboxRepo — every other port of the service stays real —
// and overrides Append with a deterministic failpoint: the call is counted
// and the injected error is returned without touching the transaction.
// Because CreateSignal performs its three writes sequentially (signal,
// audit, outbox) and returns on the first error, Append being reached
// proves the signal and audit writes of the same transaction succeeded
// before the fault; the rollback discards them (the complete-rollback
// proof). The decorator lives in the test package only.
type failingOutboxRepo struct {
	application.OutboxRepo
	cause error
	calls int
}

// Append implements application.OutboxRepo with the failpoint armed.
func (f *failingOutboxRepo) Append(ctx context.Context, tx application.Tx, ev application.OutboxEvent) error {
	f.calls++
	return f.cause
}

// countTableRows returns the row census of one table. The table name is a
// compile-time constant of this file, never caller input.
func countTableRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s rows: %v", table, err)
	}
	return n
}

// assertUTCTimestamp asserts that got carries the same instant as want and
// that it scans in time.UTC — the DEV-023 pinUTCScan contract of
// postgres.NewPool, which keeps RFC 3339 rendering independent of the host
// time zone (ARCH-001 §1: all timestamps timestamptz UTC).
func assertUTCTimestamp(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Fatalf("%s = %v, want the fixed clock time %v", what, got, want)
	}
	if got.Location() != time.UTC {
		t.Fatalf("%s location = %v, want time.UTC (pinUTCScan)", what, got.Location())
	}
}

// TestFaultInjectionCreateSignalPositivePathCommitsOneRowEach is the
// positive path of the atomicity gate: CreateSignal against the real
// repositories inside postgres.WithTx commits exactly one row each in
// risk_signals, audit_events and outbox, with the documented pending outbox
// row (dedupe key + ARCH-001 §2 payload) and the audit row linked by the
// correlation id — every timestamp UTC from the injected clock.
func TestFaultInjectionCreateSignalPositivePathCommitsOneRowEach(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := faultTestClockTime
	clk := clock.NewFakeClock(at)
	matchID := seedCreateSignalFixture(t, pool, at)
	q := gen.New(pool)
	svc := newCreateSignalService(pool, repo.NewOutboxRepo(q), clk)

	res, err := svc.CreateSignal(ctx, faultTestInput(matchID))
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	sig := res.Signal
	if sig.ID == "" || sig.MatchID != matchID {
		t.Fatalf("result signal = %+v, want a stored signal for match %s", sig, matchID)
	}
	if sig.Priority != domain.PriorityP1 || sig.Status != domain.SignalStatusNew || sig.Version != 1 {
		t.Fatalf("result signal = status %s priority %s version %d, want new/P1/1", sig.Status, sig.Priority, sig.Version)
	}
	if res.CorrelationID != faultTestCorrelationID {
		t.Fatalf("correlation id = %q, want the fixed %q", res.CorrelationID, faultTestCorrelationID)
	}

	// Exactly one row each in the three tables of the command.
	assertTableCounts(t, pool, map[string]int{"risk_signals": 1, "audit_events": 1, "outbox": 1})

	// risk_signals row: the ch. 9.3 priority, the column defaults (new/1)
	// and the clock-stamped created_at in UTC.
	var rsStatus, rsPriority string
	var rsVersion int
	var rsCreatedAt time.Time
	if err := pool.QueryRow(ctx,
		"SELECT status, priority, version, created_at FROM risk_signals").Scan(
		&rsStatus, &rsPriority, &rsVersion, &rsCreatedAt); err != nil {
		t.Fatalf("read risk_signals row: %v", err)
	}
	if rsStatus != "new" || rsPriority != "P1" || rsVersion != 1 {
		t.Fatalf("risk_signals row = %s/%s/version %d, want new/P1/1", rsStatus, rsPriority, rsVersion)
	}
	assertUTCTimestamp(t, "risk_signals created_at", rsCreatedAt, at)

	// Outbox row: pending, the command-level dedupe key and the ARCH-001 §2
	// payload with the fixed clock time and correlation id.
	var obStatus, obDedupe string
	var obPayload []byte
	var obAvailableAt, obCreatedAt time.Time
	if err := pool.QueryRow(ctx,
		"SELECT status, dedupe_key, payload, available_at, created_at FROM outbox").Scan(
		&obStatus, &obDedupe, &obPayload, &obAvailableAt, &obCreatedAt); err != nil {
		t.Fatalf("read outbox row: %v", err)
	}
	if obStatus != "pending" {
		t.Fatalf("outbox status = %q, want pending", obStatus)
	}
	if want := "signal.created:" + sig.ID; obDedupe != want {
		t.Fatalf("outbox dedupe_key = %q, want %q", obDedupe, want)
	}
	assertUTCTimestamp(t, "outbox available_at", obAvailableAt, at)
	assertUTCTimestamp(t, "outbox created_at", obCreatedAt, at)
	var payload map[string]any
	if err := json.Unmarshal(obPayload, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	assertOutboxPayload(t, payload, sig.ID, matchID, at)

	// Audit row: the signal.created action of the system actor, linked to
	// the outbox payload by the fixed correlation id, with a minimised
	// `after` snapshot and NULL `before` (a creation, ch. 13.5).
	var agType, actorType, actorID, action, corrID string
	var agID pgtype.UUID
	var occurredAt time.Time
	var beforeIsNull bool
	var after []byte
	if err := pool.QueryRow(ctx,
		`SELECT aggregate_type, aggregate_id, actor_type, actor_id, action,
		        occurred_at, before IS NULL, after, correlation_id
		 FROM audit_events`).Scan(
		&agType, &agID, &actorType, &actorID, &action,
		&occurredAt, &beforeIsNull, &after, &corrID); err != nil {
		t.Fatalf("read audit_events row: %v", err)
	}
	if agType != application.AuditAggregateRiskSignal || agID != mustUUID(t, sig.ID) {
		t.Fatalf("audit aggregate = %s/%v, want risk_signal/%s", agType, agID, sig.ID)
	}
	if action != application.EventTypeSignalCreated {
		t.Fatalf("audit action = %q, want %q", action, application.EventTypeSignalCreated)
	}
	if actorType != application.ActorTypeSystem || actorID != faultTestActorID {
		t.Fatalf("audit actor = %s/%s, want system/%s", actorType, actorID, faultTestActorID)
	}
	if corrID != faultTestCorrelationID {
		t.Fatalf("audit correlation_id = %q, want %q", corrID, faultTestCorrelationID)
	}
	if !beforeIsNull {
		t.Fatal("audit before is not NULL, want NULL for a creation")
	}
	assertUTCTimestamp(t, "audit occurred_at", occurredAt, at)
	var afterMap map[string]any
	if err := json.Unmarshal(after, &afterMap); err != nil {
		t.Fatalf("decode audit after: %v", err)
	}
	if afterMap["id"] != sig.ID || afterMap["priority"] != "P1" || afterMap["status"] != "new" {
		t.Fatalf("audit after = %v, want the minimised signal snapshot of %s (P1, new)", afterMap, sig.ID)
	}
}

// assertOutboxPayload checks the ARCH-001 §2 event shape of a decoded outbox
// payload: event_id, type signal.created, signal_id, match_id, cve_id,
// priority, occurred_at and correlation_id — all exact against the fixed
// clock time and the fixed correlation id.
func assertOutboxPayload(t *testing.T, payload map[string]any, signalID, matchID string, at time.Time) {
	t.Helper()
	if payload["type"] != application.EventTypeSignalCreated {
		t.Fatalf("payload type = %v, want %q", payload["type"], application.EventTypeSignalCreated)
	}
	eventID, _ := payload["event_id"].(string)
	if eventID == "" {
		t.Fatal("payload event_id is empty, want a uuid")
	}
	mustUUID(t, eventID) // shape check: must parse as a canonical uuid
	if payload["signal_id"] != signalID {
		t.Fatalf("payload signal_id = %v, want %s", payload["signal_id"], signalID)
	}
	if payload["match_id"] != matchID {
		t.Fatalf("payload match_id = %v, want %s", payload["match_id"], matchID)
	}
	if payload["cve_id"] != faultTestCveID {
		t.Fatalf("payload cve_id = %v, want %s", payload["cve_id"], faultTestCveID)
	}
	if payload["priority"] != "P1" {
		t.Fatalf("payload priority = %v, want P1", payload["priority"])
	}
	if want := at.Format(time.RFC3339); payload["occurred_at"] != want {
		t.Fatalf("payload occurred_at = %v, want %s", payload["occurred_at"], want)
	}
	if payload["correlation_id"] != faultTestCorrelationID {
		t.Fatalf("payload correlation_id = %v, want %s", payload["correlation_id"], faultTestCorrelationID)
	}
}

// TestFaultInjectionOutboxAppendFailureRollsBackAllWrites is the fault path
// of the atomicity gate and the literal I1b exit-criterion proof: the
// outbox append fails after the signal and audit writes of the same
// transaction succeeded. The command returns the injected error unwrapped
// and all three tables stay empty — a fault between the domain change and
// the outbox write leaves nothing behind (TR-004).
func TestFaultInjectionOutboxAppendFailureRollsBackAllWrites(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := faultTestClockTime
	clk := clock.NewFakeClock(at)
	matchID := seedCreateSignalFixture(t, pool, at)

	// The three tables of the command are empty before it runs.
	assertTableCounts(t, pool, map[string]int{"risk_signals": 0, "audit_events": 0, "outbox": 0})

	// Arm the ARCH-001 §5 seam: the real signal + audit repositories stay
	// wired; only the outbox append is decorated with the deterministic
	// failpoint (an error return — no sleep, no flake).
	q := gen.New(pool)
	cause := application.InfraError("outbox.append", errors.New("injected outbox append failure"))
	faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(q), cause: cause}
	svc := newCreateSignalService(pool, faulty, clk)

	_, err := svc.CreateSignal(ctx, faultTestInput(matchID))
	if err == nil {
		t.Fatal("CreateSignal succeeded, want the injected outbox append error")
	}
	// The error propagates unwrapped, preserving its ch. 5.2 class.
	if !errors.Is(err, cause) {
		t.Fatalf("CreateSignal error = %v, want the injected error itself (unwrapped)", err)
	}
	if kind, ok := application.ErrorKindOf(err); !ok || kind != application.KindInfra {
		t.Fatalf("CreateSignal error kind = %s (ok %v), want infrastructure", kind, ok)
	}
	// The fault seam was reached exactly once: the signal and audit writes
	// had succeeded inside the transaction before the outbox append failed
	// (CreateSignal writes sequentially and returns on the first error).
	if faulty.calls != 1 {
		t.Fatalf("outbox Append calls = %d, want 1 (the fault must hit between the audit and outbox writes)", faulty.calls)
	}

	// Complete rollback: no signal, no audit event, no outbox row is
	// observable after the failed command.
	if n := countTableRows(t, pool, "risk_signals"); n != 0 {
		t.Fatalf("risk_signals rows after rollback = %d, want 0", n)
	}
	if n := countTableRows(t, pool, "audit_events"); n != 0 {
		t.Fatalf("audit_events rows after rollback = %d, want 0", n)
	}
	if n := countTableRows(t, pool, "outbox"); n != 0 {
		t.Fatalf("outbox rows after rollback = %d, want 0", n)
	}
}
