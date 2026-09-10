package main

// Integration test of the WP-4.07 (DEV-082) I4 exit-criterion proof (c)
// (ARCH-004 §8): the atomicity fault injection of the I4 triage/SLA commands.
//
// It runs against a real, short-lived PostgreSQL through the production
// composition root: the transaction boundary is postgres.WithTx, the
// repositories are the real postgres ones and the injected FakeClock supplies
// every timestamp. The ARCH-001 §5 fault seam is reused for the I4 commands —
// the same seam the I1b CreateSignal atomicity test (DEV-024) arms — by
// decorating only the OutboxRepo with a deterministic failpoint (an error
// return, no sleep, no flake) while every other port stays real.
//
// For each of the three command shapes of the seam — AcknowledgeSignal (a
// clock fulfil), OverridePriority (the upgrade clock create + tighten) and
// TransitionSignal (a status change co-fulfilling the assessment/decision
// clocks) — the outbox append fails after the command has already written its
// state change, its audit event and its clock mutations on the same
// transaction. The command returns the injected error and every one of those
// writes is rolled back: the signal status/priority/version, the sla_clocks
// rows and the audit_events rows are exactly as they were before the command.
// No half-state — no signal-without-clock, no clock-without-audit — can exist
// (TR-004, ch. 5.1).
//
// The database server is the compose `db` service (make up) or any PostgreSQL
// reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is reachable the
// tests skip (newMigratedTestPool), so `go test ./...` stays green on machines
// without the environment.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// i4FaultClockTime is the single instant the atomicity clock reads, so the
// baseline state and the post-fault state are exact.
var i4FaultClockTime = time.Date(2026, 9, 10, 11, 0, 0, 0, time.UTC)

// newTriageServiceWithOutbox wires the triage service exactly as newTriageService
// does, but with the given OutboxRepo — the real one or the ARCH-001 §5
// failing decorator. Every other port stays the real postgres repository.
func newTriageServiceWithOutbox(pool *pgxpool.Pool, clk clock.Clock, outbox application.OutboxRepo) *application.Service {
	q := gen.New(pool)
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          outbox,
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
		PriorityRules:   repo.NewPriorityRuleRepo(q),
		FactorSource:    repo.NewPriorityFactorRepo(q),
		Clock:           clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// i4FaultCause is the deterministic injected outbox failure of the atomicity
// tests.
func i4FaultCause() error {
	return application.InfraError("outbox.append", errors.New("injected outbox append failure"))
}

// assertInjectedOutboxFault asserts the command failed with the injected
// outbox error, unwrapped, carrying the infrastructure class (ch. 5.2), and
// that the failpoint was reached exactly once (the state change, the audit and
// the clock mutations of the command had already been written inside the
// transaction before the append failed).
func assertInjectedOutboxFault(t *testing.T, err error, faulty *failingOutboxRepo) {
	t.Helper()
	if err == nil {
		t.Fatal("command succeeded, want the injected outbox append error")
	}
	if !errors.Is(err, faulty.cause) {
		t.Fatalf("command error = %v, want the injected error itself (unwrapped)", err)
	}
	if kind, ok := application.ErrorKindOf(err); !ok || kind != application.KindInfra {
		t.Fatalf("command error kind = %s (ok %v), want infrastructure", kind, ok)
	}
	if faulty.calls != 1 {
		t.Fatalf("outbox Append calls = %d, want 1 (the fault must hit after the command's writes)", faulty.calls)
	}
}

// TestI4ExitCriteriaTriageCommandAtomicity is the ARCH-004 §8 atomicity proof
// (c): an outbox-append failure inside a triage command's transaction rolls
// the signal, the clocks and the audit back completely.
func TestI4ExitCriteriaTriageCommandAtomicity(t *testing.T) {
	t.Run("acknowledge rolls back status, clock fulfil and audit", func(t *testing.T) {
		pool := newMigratedTestPool(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		at := i4FaultClockTime
		clk := clock.NewFakeClock(at)
		matchID := seedCreateSignalFixture(t, pool, at)

		good := newTriageService(pool, clk)
		created, err := good.CreateSignal(ctx, faultTestInput(matchID))
		if err != nil {
			t.Fatalf("CreateSignal: %v", err)
		}
		sig := created.Signal // P1, new, version 1

		// Baseline: one audit row + one outbox row (the create), the ack
		// clock open.
		if got := countSignalAudits(t, ctx, pool, sig.ID); got != 1 {
			t.Fatalf("baseline audits = %d, want 1", got)
		}
		if got := countTableRows(t, pool, "outbox"); got != 1 {
			t.Fatalf("baseline outbox rows = %d, want 1", got)
		}
		if ff, _, _, _ := readSlaClock(t, pool, sig.ID, domain.SLATargetAcknowledgement); ff != nil {
			t.Fatalf("baseline ack clock fulfilled_at = %v, want open", ff)
		}

		// Arm the seam: override the outbox append, keep everything else real.
		faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(gen.New(pool)), cause: i4FaultCause()}
		broken := newTriageServiceWithOutbox(pool, clk, faulty)

		_, err = broken.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
			SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: p1TestActor,
		})
		assertInjectedOutboxFault(t, err, faulty)

		// Complete rollback: status/version unchanged, ack clock still open,
		// no extra audit, no extra outbox row.
		if got := readSignalStatus(t, pool, sig.ID); got != domain.SignalStatusNew {
			t.Fatalf("status after rollback = %s, want new", got)
		}
		if got := readSignalVersion(t, pool, sig.ID); got != sig.Version {
			t.Fatalf("version after rollback = %d, want %d", got, sig.Version)
		}
		if ff, _, _, _ := readSlaClock(t, pool, sig.ID, domain.SLATargetAcknowledgement); ff != nil {
			t.Fatalf("ack clock fulfilled_at after rollback = %v, want still open", ff)
		}
		if got := countSignalAudits(t, ctx, pool, sig.ID); got != 1 {
			t.Fatalf("audits after rollback = %d, want still 1", got)
		}
		if got := countTableRows(t, pool, "outbox"); got != 1 {
			t.Fatalf("outbox rows after rollback = %d, want still 1", got)
		}
	})

	t.Run("override rolls back priority, clock create/tighten and audit", func(t *testing.T) {
		pool := newMigratedTestPool(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		at := i4FaultClockTime
		clk := clock.NewFakeClock(at)
		matchID := seedCreateSignalFixture(t, pool, at)

		good := newTriageService(pool, clk)
		created, err := good.CreateSignal(ctx, application.CreateSignalInput{
			MatchID: matchID, CveID: faultTestCveID, Factors: p3IntegrationFactors(), Actor: p1TestActor,
		})
		if err != nil {
			t.Fatalf("CreateSignal (P3): %v", err)
		}
		sig := created.Signal // P3: ack + assessment clocks, no notification/decision

		if got := countSignalAudits(t, ctx, pool, sig.ID); got != 1 {
			t.Fatalf("baseline audits = %d, want 1", got)
		}
		assertClockAt(t, pool, sig.ID, domain.SLATargetAcknowledgement, at, at.Add(24*time.Hour))
		assertClockAt(t, pool, sig.ID, domain.SLATargetAssessment, at, at.Add(72*time.Hour))
		assertNoClock(t, pool, sig.ID, domain.SLATargetNotification)
		assertNoClock(t, pool, sig.ID, domain.SLATargetDecision)

		faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(gen.New(pool)), cause: i4FaultCause()}
		broken := newTriageServiceWithOutbox(pool, clk, faulty)

		_, err = broken.OverridePriority(ctx, application.OverridePriorityInput{
			SignalID: sig.ID, Priority: domain.PriorityP1, Reason: "KEV added",
			ExpectedVersion: sig.Version, Actor: p1TestActor,
		})
		assertInjectedOutboxFault(t, err, faulty)

		// Complete rollback: still P3, no missing clock created, the existing
		// deadlines untightened, no extra audit.
		if got := readSignalPriority(t, pool, sig.ID); got != domain.PriorityP3 {
			t.Fatalf("priority after rollback = %s, want P3", got)
		}
		if got := readSignalVersion(t, pool, sig.ID); got != sig.Version {
			t.Fatalf("version after rollback = %d, want %d", got, sig.Version)
		}
		var autoPriority *string
		var overrideReason *string
		if err := pool.QueryRow(ctx, `SELECT auto_priority, override_reason FROM risk_signals WHERE id = $1`, sig.ID).
			Scan(&autoPriority, &overrideReason); err != nil {
			t.Fatalf("read override columns: %v", err)
		}
		if autoPriority != nil || overrideReason != nil {
			t.Fatalf("override columns = auto %v / reason %v, want both NULL", autoPriority, overrideReason)
		}
		assertClockAt(t, pool, sig.ID, domain.SLATargetAcknowledgement, at, at.Add(24*time.Hour))
		assertClockAt(t, pool, sig.ID, domain.SLATargetAssessment, at, at.Add(72*time.Hour))
		assertNoClock(t, pool, sig.ID, domain.SLATargetNotification)
		assertNoClock(t, pool, sig.ID, domain.SLATargetDecision)
		if got := countSignalAudits(t, ctx, pool, sig.ID); got != 1 {
			t.Fatalf("audits after rollback = %d, want still 1 (no clock-created/tightened rows)", got)
		}
		if got := countTableRows(t, pool, "outbox"); got != 1 {
			t.Fatalf("outbox rows after rollback = %d, want still 1", got)
		}
	})

	t.Run("transition rolls back status, clock co-fulfil and audit", func(t *testing.T) {
		pool := newMigratedTestPool(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		at := i4FaultClockTime
		clk := clock.NewFakeClock(at)
		matchID := seedCreateSignalFixture(t, pool, at)

		good := newTriageService(pool, clk)
		created, err := good.CreateSignal(ctx, faultTestInput(matchID))
		if err != nil {
			t.Fatalf("CreateSignal: %v", err)
		}
		sig := created.Signal // P1, new

		// Move to in_review with the real service (the ack clock is fulfilled;
		// assessment + decision stay open), so the next transition has both a
		// clock treatment and an allowed edge.
		acked, err := good.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
			SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: p1TestActor,
		})
		if err != nil {
			t.Fatalf("AcknowledgeSignal: %v", err)
		}
		if ff, _, _, _ := readSlaClock(t, pool, sig.ID, domain.SLATargetAssessment); ff != nil {
			t.Fatalf("assessment clock fulfilled before the fault, want open")
		}
		if got := countSignalAudits(t, ctx, pool, sig.ID); got != 2 {
			t.Fatalf("baseline audits = %d, want 2 (create + acknowledge)", got)
		}

		faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(gen.New(pool)), cause: i4FaultCause()}
		broken := newTriageServiceWithOutbox(pool, clk, faulty)

		_, err = broken.TransitionSignal(ctx, application.TransitionSignalInput{
			SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: acked.Version, Actor: p1TestActor,
		})
		assertInjectedOutboxFault(t, err, faulty)

		// Complete rollback: still in_review at the acknowledged version, the
		// assessment/decision clocks still open, no extra audit or outbox row.
		if got := readSignalStatus(t, pool, sig.ID); got != domain.SignalStatusInReview {
			t.Fatalf("status after rollback = %s, want in_review", got)
		}
		if got := readSignalVersion(t, pool, sig.ID); got != acked.Version {
			t.Fatalf("version after rollback = %d, want %d", got, acked.Version)
		}
		for _, target := range []domain.SLATarget{domain.SLATargetAssessment, domain.SLATargetDecision} {
			if ff, _, _, _ := readSlaClock(t, pool, sig.ID, target); ff != nil {
				t.Fatalf("%s fulfilled_at after rollback = %v, want still open", target, ff)
			}
		}
		if got := countSignalAudits(t, ctx, pool, sig.ID); got != 2 {
			t.Fatalf("audits after rollback = %d, want still 2", got)
		}
		if got := countTableRows(t, pool, "outbox"); got != 2 {
			t.Fatalf("outbox rows after rollback = %d, want still 2", got)
		}
	})
}

// readSignalVersion reads the optimistic-lock version of a signal.
func readSignalVersion(t *testing.T, pool *pgxpool.Pool, signalID string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var version int
	if err := pool.QueryRow(ctx, `SELECT version FROM risk_signals WHERE id = $1`, signalID).Scan(&version); err != nil {
		t.Fatalf("read signal version: %v", err)
	}
	return version
}

// readSignalPriority reads the effective priority of a signal.
func readSignalPriority(t *testing.T, pool *pgxpool.Pool, signalID string) domain.Priority {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var priority string
	if err := pool.QueryRow(ctx, `SELECT priority FROM risk_signals WHERE id = $1`, signalID).Scan(&priority); err != nil {
		t.Fatalf("read signal priority: %v", err)
	}
	return domain.Priority(priority)
}
