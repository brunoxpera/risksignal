package main

// Integration test of the DEV-076 SLA clock lifecycle wiring (ARCH-004
// §4.3) at the composition root: the triage commands run against a real,
// short-lived PostgreSQL behind the production postgres repositories and
// postgres.WithTx, exactly as the I5b root will wire them. It proves that
//
//   - AcknowledgeSignal fulfils the acknowledgement clock on its own
//     transaction (fulfilled_at persists), and
//   - a reopen (resolved → in_review) resets every clock defined at the
//     current priority (fresh started_at/deadline_at, fulfilled_at cleared),
//
// i.e. the fulfil + reset mutations reach the database, not just the fakes.
// The injected FakeClock supplies every instant so the deadlines are exact
// and the assertions are deterministic (ARCH-001 §3).
//
// The database server is the compose `db` service (make up) or any
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; the tests skip
// when none is reachable (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// triageClockTime is the single point in time the triage integration clock
// reads, so every persisted timestamp is exact.
var triageClockTime = time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)

// newTriageService wires the application service against the real postgres
// repositories, including the I4 triage/SLA ports (the signal repo also
// implements SignalTriageRepo). The SLA time profile is left nil, so the
// service takes the ch. 9.4 defaults — the durations the assertions use.
func newTriageService(pool *pgxpool.Pool, clk clock.Clock) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          repo.NewOutboxRepo(q),
		Vulnerabilities: repo.NewVulnerabilityRepo(q),
		Matches:         repo.NewMatchRepo(q),
		SourceRuns:      repo.NewSourceRunRepo(q),
		RawRecords:      repo.NewRawRecordRepo(q),
		Sources:         repo.NewSourceRepo(q),
		Quarantine:      repo.NewQuarantineRepo(q),
		Components:      repo.NewComponentRepo(q),
		Inventory:       repo.NewInventoryRepo(q),
		SignalTriage:    repo.NewSignalRepo(q),
		Comments:        repo.NewCommentRepo(q),
		SlaClocks:       repo.NewSlaClockRepo(q),
		Clock:           clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// p1TestActor is the system principal of the triage commands.
var p1TestActor = application.Actor{Type: application.ActorTypeSystem, ID: "integration-analyst"}

// insertSlaClock writes one open clock of a signal with a deadline at
// startedAt + d, on its own transaction, and returns nothing (the assertions
// read the row back from the database).
func insertSlaClock(t *testing.T, pool *pgxpool.Pool, signalID string, target domain.SLATarget, startedAt, deadlineAt time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	clockRepo := repo.NewSlaClockRepo(gen.New(pool))
	err := postgres.WithTx(ctx, pool, func(tx application.Tx) error {
		_, err := clockRepo.Upsert(ctx, tx, domain.SlaClock{
			SignalID:   signalID,
			Target:     target,
			StartedAt:  startedAt,
			DeadlineAt: deadlineAt,
		})
		return err
	})
	if err != nil {
		t.Fatalf("insert %s clock: %v", target, err)
	}
}

// readSlaClock reads one stored clock row back: its fulfilled_at (nil while
// open), started_at, deadline_at and accumulated pause seconds.
func readSlaClock(t *testing.T, pool *pgxpool.Pool, signalID string, target domain.SLATarget) (fulfilledAt *time.Time, startedAt, deadlineAt time.Time, pausedSeconds int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var ff pgtype.Timestamptz
	err := pool.QueryRow(ctx,
		`SELECT fulfilled_at, started_at, deadline_at, paused_seconds
		 FROM sla_clocks WHERE signal_id = $1 AND target = $2`,
		signalID, string(target)).Scan(&ff, &startedAt, &deadlineAt, &pausedSeconds)
	if err != nil {
		t.Fatalf("read %s clock: %v", target, err)
	}
	if ff.Valid {
		fulfilledAt = &ff.Time
	}
	return fulfilledAt, startedAt, deadlineAt, pausedSeconds
}

// readSignalStatus reads the stored status of a signal.
func readSignalStatus(t *testing.T, pool *pgxpool.Pool, signalID string) domain.SignalStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM risk_signals WHERE id = $1`, signalID).Scan(&status); err != nil {
		t.Fatalf("read signal status: %v", err)
	}
	return domain.SignalStatus(status)
}

// TestTriageSlaClockFulfilAndReopenResetPersist drives one P1 signal through
// acknowledge, action_planned and reopen against a real database and asserts
// the fulfilment and the reopen reset are persisted (the DEV-076 acceptance
// criterion).
func TestTriageSlaClockFulfilAndReopenResetPersist(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := triageClockTime
	clk := clock.NewFakeClock(at)
	matchID := seedCreateSignalFixture(t, pool, at)
	svc := newTriageService(pool, clk)

	created, err := svc.CreateSignal(ctx, faultTestInput(matchID))
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	sig := created.Signal // P1, new
	if sig.Priority != domain.PriorityP1 {
		t.Fatalf("signal priority = %s, want P1", sig.Priority)
	}

	// The P1 profile defines all four clocks; seed them open with a uniform
	// 24h window so the reopen's fresh windows are clearly distinguishable.
	p1Durations := map[domain.SLATarget]time.Duration{
		domain.SLATargetNotification:    5 * time.Minute,
		domain.SLATargetAcknowledgement: 15 * time.Minute,
		domain.SLATargetAssessment:      60 * time.Minute,
		domain.SLATargetDecision:        4 * time.Hour,
	}
	for target := range p1Durations {
		insertSlaClock(t, pool, sig.ID, target, at, at.Add(24*time.Hour))
	}

	// 1. Acknowledge → acknowledgement clock fulfilled in the database.
	acked, err := svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: p1TestActor,
	})
	if err != nil {
		t.Fatalf("AcknowledgeSignal: %v", err)
	}
	ff, _, _, _ := readSlaClock(t, pool, sig.ID, domain.SLATargetAcknowledgement)
	if ff == nil || !ff.Equal(at) {
		t.Fatalf("acknowledgement fulfilled_at = %v, want %v", ff, at)
	}
	if got := readSignalStatus(t, pool, sig.ID); got != domain.SignalStatusInReview {
		t.Fatalf("status = %s, want in_review", got)
	}

	// 2. → action_planned co-fulfils assessment + decision at the advanced
	// instant.
	plannedAt := at.Add(10 * time.Minute)
	clk.Advance(10 * time.Minute)
	planned, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: acked.Version, Actor: p1TestActor,
	})
	if err != nil {
		t.Fatalf("-> action_planned: %v", err)
	}
	for _, target := range []domain.SLATarget{domain.SLATargetAssessment, domain.SLATargetDecision} {
		ff, _, _, _ := readSlaClock(t, pool, sig.ID, target)
		if ff == nil || !ff.Equal(plannedAt) {
			t.Fatalf("%s fulfilled_at = %v, want %v", target, ff, plannedAt)
		}
	}
	// The notification clock is untouched by a triage transition.
	if ff, _, _, _ := readSlaClock(t, pool, sig.ID, domain.SLATargetNotification); ff != nil {
		t.Fatalf("notification fulfilled_at = %v, want still open", ff)
	}

	// 3. → resolved (closed) keeps the fulfilments (idempotent).
	resolvedAt := at.Add(20 * time.Minute)
	clk.Advance(10 * time.Minute)
	resolved, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusResolved, Reason: "patch verified",
		ExpectedVersion: planned.Version, Actor: p1TestActor,
	})
	if err != nil {
		t.Fatalf("-> resolved: %v", err)
	}
	if got := readSignalStatus(t, pool, sig.ID); got != domain.SignalStatusResolved {
		t.Fatalf("status = %s, want resolved", got)
	}

	// 4. Reopen → every defined clock is reset to a fresh window from the
	// reopen instant: fulfilled_at cleared, started_at = now and
	// deadline_at = now + duration.
	reopenAt := resolvedAt.Add(10 * time.Minute)
	clk.Advance(10 * time.Minute)
	reopened, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusInReview, Reason: "new evidence",
		ExpectedVersion: resolved.Version, Actor: p1TestActor,
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.Status != domain.SignalStatusInReview {
		t.Fatalf("reopen status = %s, want in_review", reopened.Status)
	}
	for target, d := range p1Durations {
		ff, startedAt, deadlineAt, paused := readSlaClock(t, pool, sig.ID, target)
		if ff != nil {
			t.Fatalf("%s fulfilled_at = %v after reopen, want NULL", target, ff)
		}
		if !startedAt.Equal(reopenAt) {
			t.Fatalf("%s started_at = %v, want the reopen instant %v", target, startedAt, reopenAt)
		}
		if want := reopenAt.Add(d); !deadlineAt.Equal(want) {
			t.Fatalf("%s deadline_at = %v, want %v (now + duration)", target, deadlineAt, want)
		}
		if paused != 0 {
			t.Fatalf("%s paused_seconds = %d, want 0", target, paused)
		}
	}
}
