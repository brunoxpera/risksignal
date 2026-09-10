package main

// Integration test of the WP-4.07 (DEV-082) I4 exit-criterion proof (b)
// (ARCH-004 §8): the accelerated SLA lifecycle on the injected FakeClock.
//
// cmd/risksignal-worker is the composition root that wires the outbox relay,
// the notify handler (WP-4.06 / DEV-081) and the sla.evaluate scheduler
// (WP-4.05 / DEV-080) exactly as production runs them; the test drives the
// real application use cases (CreateSignal, AcknowledgeSignal, TransitionSignal,
// OverridePriority, PauseSla/ResumeSla) behind the postgres repositories on
// postgres.WithTx against a real, short-lived PostgreSQL. A scaled
// SLATimeProfile (seconds instead of minutes/hours) and a scaled reminder
// cadence make every duration tiny, so the whole lifecycle runs instantly on
// the FakeClock without real waiting — the escalation/status/audit logic is
// never touched (FR-032, NFR-015).
//
// Three proofs:
//
//   (i)   the full P1 lifecycle: create (all four clocks + the signal.created
//         notification) → delivery (the notify handler fulfils the
//         notification clock) → acknowledge (ack clock fulfilled, → in_review)
//         → action_planned (assessment + decision co-fulfilled) → resolve
//         (closed_at set) → reopen (every clock reset, closed_at cleared);
//   (ii)  an unacknowledged P1 escalates exactly once (one signal.escalated
//         outbox event + one audit row, escalated_at stamped once) and then
//         emits one reminder per cadence window (dedupe-keyed, audited);
//   (iii) a P3→P1 upgrade creates the missing notification/decision clocks and
//         tightens the pre-existing acknowledgement/assessment deadlines, and
//         pause/resume accumulates paused_seconds (the effective deadline
//         moves out by exactly the paused time).
//
// The database server is the compose `db` service (make up) or any PostgreSQL
// reachable through RISKSIGNAL_TEST_DATABASE_URL; the tests skip when none is
// reachable (newMigratedWorkerPool), so `go test ./...` stays green on machines
// without the environment.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/notify"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/worker"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// i4ExitSlaClockTime is the single instant the accelerated lifecycle clock
// reads. It lies comfortably in the past relative to the database wall clock
// so the relay's available_at <= now() claim always picks up the rows the
// commands enqueue at the (earlier) fake instant.
var i4ExitSlaClockTime = time.Date(2026, 9, 10, 6, 0, 0, 0, time.UTC)

// i4ExitScaledProfile is the accelerated (priority, target) → duration profile:
// the ch. 9.4 shape (P1 notifies/decides, P2 per FR-023, P3/P4 carry only the
// ack/assessment clocks) at second scale instead of minutes/hours.
func i4ExitScaledProfile(t *testing.T) domain.SLATimeProfile {
	t.Helper()
	profile, err := domain.NewSLATimeProfile(map[domain.Priority]map[domain.SLATarget]time.Duration{
		domain.PriorityP1: {
			domain.SLATargetNotification:    1 * time.Second,
			domain.SLATargetAcknowledgement: 2 * time.Second,
			domain.SLATargetAssessment:      5 * time.Second,
			domain.SLATargetDecision:        8 * time.Second,
		},
		domain.PriorityP2: {
			domain.SLATargetNotification:    1 * time.Second,
			domain.SLATargetAcknowledgement: 3 * time.Second,
			domain.SLATargetAssessment:      6 * time.Second,
			domain.SLATargetDecision:        10 * time.Second,
		},
		domain.PriorityP3: {
			domain.SLATargetAcknowledgement: 4 * time.Second,
			domain.SLATargetAssessment:      7 * time.Second,
		},
		domain.PriorityP4: {
			domain.SLATargetAssessment: 9 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSLATimeProfile: %v", err)
	}
	return profile
}

// i4ExitReminderCadence is the scaled escalation reminder cadence (production
// default is one hour).
const i4ExitReminderCadence = 2 * time.Second

// i4ExitActor is the system principal of the accelerated lifecycle commands.
var i4ExitActor = application.Actor{Type: application.ActorTypeSystem, ID: "i4-exit-analyst"}

// i4ExitService wires the application service on the real postgres repositories
// exactly as cmd/risksignal-worker/main.go does, with the scaled SLA profile,
// the scaled reminder cadence and the injected FakeClock.
func i4ExitService(t *testing.T, pool *pgxpool.Pool, clk clock.Clock, profile domain.SLATimeProfile) *application.Service {
	t.Helper()
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
		SignalTriage:       repo.NewSignalRepo(q),
		Comments:           repo.NewCommentRepo(q),
		SlaClocks:          repo.NewSlaClockRepo(q),
		PriorityRules:      repo.NewPriorityRuleRepo(q),
		FactorSource:       repo.NewPriorityFactorRepo(q),
		SlaTimeProfile:     &profile,
		SLAReminderCadence: i4ExitReminderCadence,
		Clock:              clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// i4ExitNotifyRelay wires the notify handler (in-app only — no SMTP/webhook
// target, so the accelerated digest is network-free) on the real outbox relay
// over the postgres OutboxStore, exactly as the worker root does.
func i4ExitNotifyRelay(t *testing.T, pool *pgxpool.Pool, clk clock.Clock) *worker.Relay {
	t.Helper()
	q := gen.New(pool)
	jobs, err := worker.NewNotifyJobs(worker.NotifyJobsDeps{
		Notifications: repo.NewNotificationRepo(q),
		SlaClocks:     repo.NewSlaClockRepo(q),
		Port: notify.NewDispatcher(map[notify.NotifyChannel]notify.NotifyPort{
			notify.ChannelInApp: notify.NewInAppPort(),
		}),
		Policy: worker.NotifyPolicy{}, // in-app only
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
		Clock:  clk,
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewNotifyJobs: %v", err)
	}
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), discardLogger())
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	return relay
}

// i4ExitSeedMatch seeds the asset/component/vulnerability/match chain backing
// one signal and returns the match id (risk_signals is UQ on match_id).
func i4ExitSeedMatch(t *testing.T, ctx context.Context, q *gen.Queries, at time.Time, cveID string) string {
	t.Helper()
	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID: "i4exit-asset", Source: "demo", Type: "server_vm", Name: "I4 Exit",
		Environment: "production", Criticality: "critical", Exposure: "internet", Owner: pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	naturalKey, err := domain.ComponentNaturalKey(
		domain.ComponentIdentifiers{Vendor: "acme", Product: "i4exit", Version: "1.0"}, "acme", "i4exit", "")
	if err != nil {
		t.Fatalf("ComponentNaturalKey: %v", err)
	}
	componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID: assetID, Vendor: "acme", Product: "i4exit", Version: "1.0",
		VendorNorm: "acme", ProductNorm: "i4exit",
		VersionScheme: string(domain.VersionSchemeUnknown), NaturalKey: naturalKey,
		UpdatedAt: pgtype.Timestamptz{Time: at, Valid: true},
	})
	if err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: cveID, Summary: "i4 exit accelerated lifecycle",
		PublishedAt: pgtype.Timestamptz{Time: at.AddDate(0, 0, -30), Valid: true},
		ModifiedAt:  pgtype.Timestamptz{Time: at.AddDate(0, 0, -1), Valid: true},
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}
	matchID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID, ComponentID: componentID, Method: string(domain.MatchMethodExactIdentifier),
		Score: 100, Confidence: string(domain.ConfidenceHigh), RuleVersion: domain.MatchRuleVersion,
		CreatedAt: pgtype.Timestamptz{Time: at, Valid: true}, Reasons: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("InsertMatch: %v", err)
	}
	return uuidStr(matchID)
}

// i4ExitP1Factors is the ch. 9.3 P1 factor set (high + KEV + critical/internet).
func i4ExitP1Factors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
		KEV: true, CVSS: 9.8, EPSS: 0.99, Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
	}
}

// i4ExitP3Factors is a ch. 9.3 P3 factor set (high with no strong urgency).
func i4ExitP3Factors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method: domain.MatchMethodExactIdentifier, Confidence: domain.ConfidenceHigh,
		KEV: false, CVSS: 5.0, EPSS: 0.1, Criticality: domain.CriticalityLow, Exposure: domain.ExposureInternal,
	}
}

// i4ExitClock reads one stored clock: its fulfilled_at (nil while open), the
// frozen started_at/deadline_at and the accumulated paused_seconds.
func i4ExitClock(t *testing.T, pool *pgxpool.Pool, signalID string, target domain.SLATarget) (*time.Time, time.Time, time.Time, int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var fulfilled pgtype.Timestamptz
	var startedAt, deadlineAt time.Time
	var paused int64
	if err := pool.QueryRow(ctx,
		`SELECT fulfilled_at, started_at, deadline_at, paused_seconds
		 FROM sla_clocks WHERE signal_id = $1 AND target = $2`, signalID, string(target)).
		Scan(&fulfilled, &startedAt, &deadlineAt, &paused); err != nil {
		t.Fatalf("read %s clock: %v", target, err)
	}
	if !fulfilled.Valid {
		return nil, startedAt, deadlineAt, paused
	}
	at := fulfilled.Time
	return &at, startedAt, deadlineAt, paused
}

// i4ExitHasClock reports whether a clock exists for the target.
func i4ExitHasClock(t *testing.T, pool *pgxpool.Pool, signalID string, target domain.SLATarget) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM sla_clocks WHERE signal_id = $1 AND target = $2`, signalID, string(target)).Scan(&n); err != nil {
		t.Fatalf("count %s clock: %v", target, err)
	}
	return n > 0
}

// i4ExitSignalStatus reads the stored status of a signal.
func i4ExitSignalStatus(t *testing.T, pool *pgxpool.Pool, signalID string) domain.SignalStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM risk_signals WHERE id = $1`, signalID).Scan(&status); err != nil {
		t.Fatalf("read signal status: %v", err)
	}
	return domain.SignalStatus(status)
}

// i4ExitClosedAt reads the closed_at of a signal (nil while open).
func i4ExitClosedAt(t *testing.T, pool *pgxpool.Pool, signalID string) *time.Time {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var closed pgtype.Timestamptz
	if err := pool.QueryRow(ctx, `SELECT closed_at FROM risk_signals WHERE id = $1`, signalID).Scan(&closed); err != nil {
		t.Fatalf("read closed_at: %v", err)
	}
	if !closed.Valid {
		return nil
	}
	at := closed.Time
	return &at
}

// i4ExitEscalatedAt reads the escalated_at of a signal (nil when never
// escalated).
func i4ExitEscalatedAt(t *testing.T, pool *pgxpool.Pool, signalID string) *time.Time {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var escalated pgtype.Timestamptz
	if err := pool.QueryRow(ctx, `SELECT escalated_at FROM risk_signals WHERE id = $1`, signalID).Scan(&escalated); err != nil {
		t.Fatalf("read escalated_at: %v", err)
	}
	if !escalated.Valid {
		return nil
	}
	at := escalated.Time
	return &at
}

// i4ExitCountOutboxType counts the outbox rows of one type.
func i4ExitCountOutboxType(t *testing.T, pool *pgxpool.Pool, typ string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE type = $1`, typ).Scan(&n); err != nil {
		t.Fatalf("count outbox type %s: %v", typ, err)
	}
	return n
}

// i4ExitCountAuditAction counts the audit rows of one action.
func i4ExitCountAuditAction(t *testing.T, pool *pgxpool.Pool, action string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatalf("count audit action %s: %v", action, err)
	}
	return n
}

// i4ExitReminderDedupeKeys returns the dedupe keys of the reminder outbox rows.
func i4ExitReminderDedupeKeys(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx, `SELECT dedupe_key FROM outbox WHERE type = $1 ORDER BY dedupe_key`, application.EventTypeSignalReminder)
	if err != nil {
		t.Fatalf("read reminder dedupe keys: %v", err)
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatalf("scan dedupe key: %v", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read reminder dedupe keys: %v", err)
	}
	return keys
}

// TestI4ExitCriteriaAcceleratedSlaLifecycle is proof (b)(i): one P1 signal
// driven through the whole lifecycle — create → deliver → acknowledge →
// action_planned → resolve → reopen — asserting the clock treatment and the
// persisted state at every step.
func TestI4ExitCriteriaAcceleratedSlaLifecycle(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := i4ExitSlaClockTime
	clk := clock.NewFakeClock(at)
	profile := i4ExitScaledProfile(t)
	svc := i4ExitService(t, pool, clk, profile)
	relay := i4ExitNotifyRelay(t, pool, clk)
	matchID := i4ExitSeedMatch(t, ctx, gen.New(pool), at, "CVE-2026-7001")

	// Create: P1, new, all four clocks at the scaled P1 durations.
	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID, CveID: "CVE-2026-7001", Factors: i4ExitP1Factors(), Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	sig := created.Signal
	if sig.Priority != domain.PriorityP1 || sig.Status != domain.SignalStatusNew {
		t.Fatalf("created signal = %s/%s, want P1/new", sig.Priority, sig.Status)
	}
	p1 := map[domain.SLATarget]time.Duration{
		domain.SLATargetNotification:    1 * time.Second,
		domain.SLATargetAcknowledgement: 2 * time.Second,
		domain.SLATargetAssessment:      5 * time.Second,
		domain.SLATargetDecision:        8 * time.Second,
	}
	for target, d := range p1 {
		ff, startedAt, deadlineAt, _ := i4ExitClock(t, pool, sig.ID, target)
		if ff != nil {
			t.Fatalf("%s clock fulfilled at create, want open", target)
		}
		if !startedAt.Equal(at) || !deadlineAt.Equal(at.Add(d)) {
			t.Fatalf("%s clock = start %v / deadline %v, want %v / %v", target, startedAt, deadlineAt, at, at.Add(d))
		}
	}

	// Delivery: the notify handler fulfils the notification clock at `at`.
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("delivery drain: %v", err)
	}
	if n := countNotificationsByChannel(t, ctx, pool, sig.ID, "in_app"); n != 1 {
		t.Fatalf("in_app notifications after create delivery = %d, want 1", n)
	}
	if status, _, _, _ := readNotification(t, ctx, pool, sig.ID, "in_app"); status != "delivered" {
		t.Fatalf("in_app notification = %s, want delivered", status)
	}
	if ff := readNotificationClockFulfilled(t, ctx, pool, sig.ID); ff == nil || !ff.Equal(at) {
		t.Fatalf("notification clock fulfilled_at = %v, want %v (on delivery)", ff, at)
	}

	// Acknowledge at T0+500ms: ack clock fulfilled, → in_review.
	clk.Advance(500 * time.Millisecond)
	ackAt := at.Add(500 * time.Millisecond)
	acked, err := svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("AcknowledgeSignal: %v", err)
	}
	if got := i4ExitSignalStatus(t, pool, sig.ID); got != domain.SignalStatusInReview {
		t.Fatalf("status after acknowledge = %s, want in_review", got)
	}
	if ff, _, _, _ := i4ExitClock(t, pool, sig.ID, domain.SLATargetAcknowledgement); ff == nil || !ff.Equal(ackAt) {
		t.Fatalf("ack clock fulfilled_at = %v, want %v", ff, ackAt)
	}

	// → action_planned at T0+1s: assessment + decision co-fulfilled.
	clk.Advance(500 * time.Millisecond)
	plannedAt := at.Add(1 * time.Second)
	planned, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: acked.Version, Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("-> action_planned: %v", err)
	}
	for _, target := range []domain.SLATarget{domain.SLATargetAssessment, domain.SLATargetDecision} {
		if ff, _, _, _ := i4ExitClock(t, pool, sig.ID, target); ff == nil || !ff.Equal(plannedAt) {
			t.Fatalf("%s fulfilled_at = %v, want %v", target, ff, plannedAt)
		}
	}

	// → resolved at T0+1.5s: closed_at set, the fulfilments kept.
	clk.Advance(500 * time.Millisecond)
	resolvedAt := at.Add(1500 * time.Millisecond)
	resolved, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusResolved, Reason: "patch verified",
		ExpectedVersion: planned.Version, Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("-> resolved: %v", err)
	}
	if got := i4ExitSignalStatus(t, pool, sig.ID); got != domain.SignalStatusResolved {
		t.Fatalf("status after resolve = %s, want resolved", got)
	}
	if closed := i4ExitClosedAt(t, pool, sig.ID); closed == nil || !closed.Equal(resolvedAt) {
		t.Fatalf("closed_at = %v, want %v", closed, resolvedAt)
	}

	// Reopen at T0+2.5s: every defined clock reset, closed_at cleared.
	clk.Advance(1 * time.Second)
	reopenAt := at.Add(2500 * time.Millisecond)
	if _, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusInReview, Reason: "new evidence",
		ExpectedVersion: resolved.Version, Actor: i4ExitActor,
	}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := i4ExitSignalStatus(t, pool, sig.ID); got != domain.SignalStatusInReview {
		t.Fatalf("status after reopen = %s, want in_review", got)
	}
	if closed := i4ExitClosedAt(t, pool, sig.ID); closed != nil {
		t.Fatalf("closed_at after reopen = %v, want NULL (retention countdown stopped)", closed)
	}
	for target, d := range p1 {
		ff, startedAt, deadlineAt, paused := i4ExitClock(t, pool, sig.ID, target)
		if ff != nil {
			t.Fatalf("%s fulfilled_at after reopen = %v, want NULL", target, ff)
		}
		if !startedAt.Equal(reopenAt) || !deadlineAt.Equal(reopenAt.Add(d)) {
			t.Fatalf("%s reset = start %v / deadline %v, want %v / %v", target, startedAt, deadlineAt, reopenAt, reopenAt.Add(d))
		}
		if paused != 0 {
			t.Fatalf("%s paused_seconds after reopen = %d, want 0", target, paused)
		}
	}
}

// TestI4ExitCriteriaUnacknowledgedP1Escalation is proof (b)(ii): an
// unacknowledged P1 escalates exactly once through the sla.evaluate scheduler
// and then emits one reminder per cadence window.
func TestI4ExitCriteriaUnacknowledgedP1Escalation(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := i4ExitSlaClockTime
	clk := clock.NewFakeClock(at)
	profile := i4ExitScaledProfile(t)
	svc := i4ExitService(t, pool, clk, profile)
	relay := i4ExitNotifyRelay(t, pool, clk)
	matchID := i4ExitSeedMatch(t, ctx, gen.New(pool), at, "CVE-2026-7002")

	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID, CveID: "CVE-2026-7002", Factors: i4ExitP1Factors(), Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	sig := created.Signal
	if err := relay.Drain(ctx); err != nil { // deliver the signal.created notification
		t.Fatalf("create drain: %v", err)
	}
	if escalated := i4ExitEscalatedAt(t, pool, sig.ID); escalated != nil {
		t.Fatalf("escalated_at = %v before the ack deadline, want NULL", escalated)
	}

	sched, err := worker.NewSlaSchedule(svc, clk, 1*time.Second, discardLogger())
	if err != nil {
		t.Fatalf("NewSlaSchedule: %v", err)
	}

	// Cross the ack deadline (2s) and tick: exactly one escalation.
	clk.Set(at.Add(2500 * time.Millisecond))
	escalatedAt := at.Add(2500 * time.Millisecond)
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("tick after ack breach: %v", err)
	}
	if got := i4ExitEscalatedAt(t, pool, sig.ID); got == nil || !got.Equal(escalatedAt) {
		t.Fatalf("escalated_at = %v, want %v", got, escalatedAt)
	}
	if n := i4ExitCountOutboxType(t, pool, application.EventTypeSignalEscalated); n != 1 {
		t.Fatalf("signal.escalated outbox rows = %d, want exactly 1", n)
	}
	if n := i4ExitCountAuditAction(t, pool, application.EventTypeSignalEscalated); n != 1 {
		t.Fatalf("signal.escalated audit rows = %d, want exactly 1", n)
	}

	// A further tick (cadence elapsed) escalates nothing: the set-once guard.
	clk.Set(escalatedAt.Add(1 * time.Second))
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("tick after escalation: %v", err)
	}
	if n := i4ExitCountOutboxType(t, pool, application.EventTypeSignalEscalated); n != 1 {
		t.Fatalf("signal.escalated outbox rows after a second tick = %d, want still 1 (escalate once)", n)
	}
	if n := i4ExitCountAuditAction(t, pool, application.EventTypeSignalEscalated); n != 1 {
		t.Fatalf("signal.escalated audit rows after a second tick = %d, want still 1", n)
	}

	// Reminders: one per cadence window (2s), dedupe-keyed and audited once.
	clk.Set(escalatedAt.Add(2 * time.Second)) // window 1
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("tick for reminder 1: %v", err)
	}
	if n := i4ExitCountOutboxType(t, pool, application.EventTypeSignalReminder); n != 1 {
		t.Fatalf("reminder outbox rows = %d, want 1", n)
	}
	if n := i4ExitCountAuditAction(t, pool, application.EventTypeSignalReminder); n != 1 {
		t.Fatalf("reminder audit rows = %d, want 1", n)
	}

	// A tick inside the same window dedupes (no second reminder).
	clk.Set(escalatedAt.Add(3 * time.Second))
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("tick inside window 1: %v", err)
	}
	if n := i4ExitCountOutboxType(t, pool, application.EventTypeSignalReminder); n != 1 {
		t.Fatalf("reminder outbox rows inside the same window = %d, want still 1", n)
	}

	// The next window appends a fresh reminder.
	clk.Set(escalatedAt.Add(4 * time.Second)) // window 2
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("tick for reminder 2: %v", err)
	}
	if n := i4ExitCountOutboxType(t, pool, application.EventTypeSignalReminder); n != 2 {
		t.Fatalf("reminder outbox rows after window 2 = %d, want 2", n)
	}
	wantKeys := []string{
		application.EventTypeSignalReminder + ":" + sig.ID + ":1",
		application.EventTypeSignalReminder + ":" + sig.ID + ":2",
	}
	if got := i4ExitReminderDedupeKeys(t, pool); len(got) != 2 || got[0] != wantKeys[0] || got[1] != wantKeys[1] {
		t.Fatalf("reminder dedupe keys = %v, want %v", got, wantKeys)
	}

	// Delivery: the escalation + both reminders are delivered once; a
	// redelivery drain is a no-op (idempotent on the outbox event id).
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("escalation drain: %v", err)
	}
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("redelivery drain: %v", err)
	}
	var escalatedNotifs, reminderNotifs int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE kind = $1), count(*) FILTER (WHERE kind = $2)
		 FROM notifications WHERE signal_id = $3`,
		application.EventTypeSignalEscalated, application.EventTypeSignalReminder, sig.ID).
		Scan(&escalatedNotifs, &reminderNotifs); err != nil {
		t.Fatalf("count escalation/reminder notifications: %v", err)
	}
	if escalatedNotifs != 1 {
		t.Fatalf("signal.escalated notifications = %d, want 1", escalatedNotifs)
	}
	if reminderNotifs != 2 {
		t.Fatalf("reminder notifications = %d, want 2 (one per window, no duplicate)", reminderNotifs)
	}
}

// TestI4ExitCriteriaPriorityUpgradeAndPauseResume is proof (b)(iii): a P3→P1
// override creates the missing clocks and tightens the existing ones (audited
// per mutation), and pause/resume accumulates the paused time in
// paused_seconds.
func TestI4ExitCriteriaPriorityUpgradeAndPauseResume(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := i4ExitSlaClockTime
	clk := clock.NewFakeClock(at)
	profile := i4ExitScaledProfile(t)
	svc := i4ExitService(t, pool, clk, profile)

	// --- Upgrade: P3 → P1 ------------------------------------------------
	matchID := i4ExitSeedMatch(t, ctx, gen.New(pool), at, "CVE-2026-7003")
	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID, CveID: "CVE-2026-7003", Factors: i4ExitP3Factors(), Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("CreateSignal (P3): %v", err)
	}
	sig := created.Signal
	if sig.Priority != domain.PriorityP3 {
		t.Fatalf("created priority = %s, want P3", sig.Priority)
	}
	// P3: ack (4s) + assessment (7s), no notification/decision.
	if _, started, deadline, _ := i4ExitClock(t, pool, sig.ID, domain.SLATargetAcknowledgement); !started.Equal(at) || !deadline.Equal(at.Add(4*time.Second)) {
		t.Fatalf("P3 ack clock = %v / %v, want %v / %v", started, deadline, at, at.Add(4*time.Second))
	}
	if _, started, deadline, _ := i4ExitClock(t, pool, sig.ID, domain.SLATargetAssessment); !started.Equal(at) || !deadline.Equal(at.Add(7*time.Second)) {
		t.Fatalf("P3 assessment clock = %v / %v, want %v / %v", started, deadline, at, at.Add(7*time.Second))
	}
	if i4ExitHasClock(t, pool, sig.ID, domain.SLATargetNotification) || i4ExitHasClock(t, pool, sig.ID, domain.SLATargetDecision) {
		t.Fatal("P3 signal carries a notification/decision clock, want none")
	}

	clk.Set(at.Add(1 * time.Second))
	upgradeAt := at.Add(1 * time.Second)
	up, err := svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP1, Reason: "KEV added",
		ExpectedVersion: sig.Version, Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}
	if up.Priority != domain.PriorityP1 {
		t.Fatalf("overridden priority = %s, want P1", up.Priority)
	}
	// Missing clocks created from the upgrade instant.
	if _, started, deadline, _ := i4ExitClock(t, pool, sig.ID, domain.SLATargetNotification); !started.Equal(upgradeAt) || !deadline.Equal(upgradeAt.Add(1*time.Second)) {
		t.Fatalf("upgraded notification clock = %v / %v, want %v / %v", started, deadline, upgradeAt, upgradeAt.Add(1*time.Second))
	}
	if _, started, deadline, _ := i4ExitClock(t, pool, sig.ID, domain.SLATargetDecision); !started.Equal(upgradeAt) || !deadline.Equal(upgradeAt.Add(8*time.Second)) {
		t.Fatalf("upgraded decision clock = %v / %v, want %v / %v", started, deadline, upgradeAt, upgradeAt.Add(8*time.Second))
	}
	// Existing clocks tightened, started_at preserved at the create instant.
	if _, started, deadline, _ := i4ExitClock(t, pool, sig.ID, domain.SLATargetAcknowledgement); !started.Equal(at) || !deadline.Equal(upgradeAt.Add(2*time.Second)) {
		t.Fatalf("upgraded ack clock = %v / %v, want %v / %v", started, deadline, at, upgradeAt.Add(2*time.Second))
	}
	if _, started, deadline, _ := i4ExitClock(t, pool, sig.ID, domain.SLATargetAssessment); !started.Equal(at) || !deadline.Equal(upgradeAt.Add(5*time.Second)) {
		t.Fatalf("upgraded assessment clock = %v / %v, want %v / %v", started, deadline, at, upgradeAt.Add(5*time.Second))
	}
	if createdAudits, tightenedAudits := i4ExitCountAuditAction(t, pool, application.EventTypeSignalSLAClockCreated),
		i4ExitCountAuditAction(t, pool, application.EventTypeSignalSLAClockTightened); createdAudits != 2 || tightenedAudits != 2 {
		t.Fatalf("upgrade clock audits = %d created / %d tightened, want 2 / 2", createdAudits, tightenedAudits)
	}

	// --- Pause / resume --------------------------------------------------
	// The second signal's clocks start at the base instant again (the clock is
	// returned to `at`), independent of the upgrade above.
	clk.Set(at)
	matchID2 := i4ExitSeedMatch(t, ctx, gen.New(pool), at, "CVE-2026-7004")
	created2, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID2, CveID: "CVE-2026-7004", Factors: i4ExitP1Factors(), Actor: i4ExitActor,
	})
	if err != nil {
		t.Fatalf("CreateSignal (P1): %v", err)
	}
	sig2 := created2.Signal
	if _, _, deadline, _ := i4ExitClock(t, pool, sig2.ID, domain.SLATargetAcknowledgement); !deadline.Equal(at.Add(2 * time.Second)) {
		t.Fatalf("P1 ack deadline = %v, want %v", deadline, at.Add(2*time.Second))
	}

	pauseAt := at.Add(500 * time.Millisecond)
	clk.Set(pauseAt)
	if _, err := svc.PauseSla(ctx, application.PauseSlaInput{
		SignalID: sig2.ID, Target: domain.SLATargetAcknowledgement, Reason: "awaiting vendor", Actor: i4ExitActor,
	}); err != nil {
		t.Fatalf("PauseSla: %v", err)
	}
	if _, _, _, paused := i4ExitClock(t, pool, sig2.ID, domain.SLATargetAcknowledgement); paused != 0 {
		t.Fatalf("paused_seconds while paused = %d, want 0 (not yet accumulated)", paused)
	}

	resumeAt := pauseAt.Add(3 * time.Second)
	clk.Set(resumeAt)
	if _, err := svc.ResumeSla(ctx, application.ResumeSlaInput{
		SignalID: sig2.ID, Target: domain.SLATargetAcknowledgement, Reason: "vendor replied", Actor: i4ExitActor,
	}); err != nil {
		t.Fatalf("ResumeSla: %v", err)
	}
	ff, startedAt, deadlineAt, paused := i4ExitClock(t, pool, sig2.ID, domain.SLATargetAcknowledgement)
	if ff != nil {
		t.Fatalf("ack clock fulfilled_at = %v after resume, want open", ff)
	}
	if !startedAt.Equal(at) || !deadlineAt.Equal(at.Add(2*time.Second)) {
		t.Fatalf("ack clock window = %v / %v, want the frozen %v / %v", startedAt, deadlineAt, at, at.Add(2*time.Second))
	}
	if paused != 3 {
		t.Fatalf("paused_seconds after resume = %d, want 3 (the 3s pause accumulated)", paused)
	}
	// The effective deadline moves out by exactly the paused time.
	if want := deadlineAt.Add(time.Duration(paused) * time.Second); !want.Equal(at.Add(5 * time.Second)) {
		t.Fatalf("effective deadline = %v, want %v", want, at.Add(5*time.Second))
	}
}
