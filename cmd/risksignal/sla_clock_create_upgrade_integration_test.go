package main

// Integration test of the DEV-079 SLA clock lifecycle at the composition root
// (ARCH-004 §4.3): the create and the priority-upgrade clock treatment run
// against a real, short-lived PostgreSQL behind the production postgres
// repositories and postgres.WithTx. It proves that
//
//   - CreateSignal creates exactly the clocks the signal's priority defines
//     (a P3 signal gets its acknowledgement + assessment clocks and no
//     notification/decision clock), and
//   - a P3→P1 override creates the missing notification/decision clocks from
//     the upgrade instant and tightens the pre-existing acknowledgement and
//     assessment clocks to the new, earlier deadlines — keeping their
//     started_at — with every mutation audited,
//
// i.e. the create and the tighten reach the database, not just the fakes. The
// injected FakeClock supplies every instant so the deadlines are exact and the
// assertions are deterministic (ARCH-001 §3).
//
// The database server is the compose `db` service (make up) or any PostgreSQL
// reachable through RISKSIGNAL_TEST_DATABASE_URL; the tests skip when none is
// reachable (newTestDB), so `go test ./...` stays green on machines without
// the environment.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// createUpgradeClockTime is the single point in time the create/upgrade
// integration clock reads, so every persisted timestamp is exact.
var createUpgradeClockTime = time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)

// p3IntegrationFactors is a factor set the ch. 9.3 rules resolve to P3: a
// plausible, high-confidence assignment without a strong urgency indicator.
func p3IntegrationFactors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method:      domain.MatchMethodExactIdentifier,
		Confidence:  domain.ConfidenceHigh,
		KEV:         false,
		CVSS:        5.0,
		EPSS:        0.1,
		Criticality: domain.CriticalityLow,
		Exposure:    domain.ExposureInternal,
	}
}

// readClockStartedDeadline reads one stored clock's started_at and
// deadline_at; ok is false when no clock exists for the target.
func readClockStartedDeadline(t *testing.T, pool *pgxpool.Pool, signalID string, target domain.SLATarget) (startedAt, deadlineAt time.Time, ok bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := pool.QueryRow(ctx,
		`SELECT started_at, deadline_at FROM sla_clocks WHERE signal_id = $1 AND target = $2`,
		signalID, string(target)).Scan(&startedAt, &deadlineAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, time.Time{}, false
	}
	if err != nil {
		t.Fatalf("read %s clock: %v", target, err)
	}
	return startedAt, deadlineAt, true
}

// assertClockAt asserts one stored clock starts at startedAt and is due at
// deadlineAt.
func assertClockAt(t *testing.T, pool *pgxpool.Pool, signalID string, target domain.SLATarget, startedAt, deadlineAt time.Time) {
	t.Helper()
	gotStarted, gotDeadline, ok := readClockStartedDeadline(t, pool, signalID, target)
	if !ok {
		t.Fatalf("%s clock missing", target)
	}
	if !gotStarted.Equal(startedAt) {
		t.Fatalf("%s started_at = %v, want %v", target, gotStarted, startedAt)
	}
	if !gotDeadline.Equal(deadlineAt) {
		t.Fatalf("%s deadline_at = %v, want %v", target, gotDeadline, deadlineAt)
	}
}

// assertNoClock asserts no clock exists for the target.
func assertNoClock(t *testing.T, pool *pgxpool.Pool, signalID string, target domain.SLATarget) {
	t.Helper()
	if _, _, ok := readClockStartedDeadline(t, pool, signalID, target); ok {
		t.Fatalf("%s clock exists, want none", target)
	}
}

// countClockAudits counts the clock-created and clock-tightened audit rows of
// one signal.
func countClockAudits(t *testing.T, pool *pgxpool.Pool, signalID string) (created, tightened int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		`SELECT action FROM audit_events WHERE aggregate_id = $1`, mustUUID(t, signalID))
	if err != nil {
		t.Fatalf("read audit actions: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatalf("scan audit action: %v", err)
		}
		switch action {
		case application.EventTypeSignalSLAClockCreated:
			created++
		case application.EventTypeSignalSLAClockTightened:
			tightened++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read audit actions: %v", err)
	}
	return created, tightened
}

// TestCreateAndUpgradeClockLifecyclePersists drives one P3 signal through the
// create and a P3→P1 upgrade against a real database and asserts the clocks
// and their audit rows persist (the DEV-079 acceptance criterion).
func TestCreateAndUpgradeClockLifecyclePersists(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := createUpgradeClockTime
	clk := clock.NewFakeClock(at)
	matchID := seedCreateSignalFixture(t, pool, at)
	svc := newTriageService(pool, clk)

	// 1. Create a P3 signal: the create writes only the P3 clocks.
	created, err := svc.CreateSignal(ctx, application.CreateSignalInput{
		MatchID: matchID,
		CveID:   faultTestCveID,
		Factors: p3IntegrationFactors(),
		Actor:   p1TestActor,
	})
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	sig := created.Signal
	if sig.Priority != domain.PriorityP3 {
		t.Fatalf("created priority = %s, want P3", sig.Priority)
	}
	assertClockAt(t, pool, sig.ID, domain.SLATargetAcknowledgement, at, at.Add(24*time.Hour))
	assertClockAt(t, pool, sig.ID, domain.SLATargetAssessment, at, at.Add(72*time.Hour))
	assertNoClock(t, pool, sig.ID, domain.SLATargetNotification)
	assertNoClock(t, pool, sig.ID, domain.SLATargetDecision)
	if got, _ := countClockAudits(t, pool, sig.ID); got != 0 {
		t.Fatalf("clock-created audits after the create = %d, want 0 (the create's own audit is the evidence)", got)
	}

	// 2. Upgrade to P1 half an hour later: the missing clocks are created, the
	// existing ones tightened, every mutation audited.
	const delta = 30 * time.Minute
	clk.Advance(delta)
	upgradeAt := at.Add(delta)

	up, err := svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID:        sig.ID,
		Priority:        domain.PriorityP1,
		Reason:          "KEV added",
		ExpectedVersion: sig.Version,
		Actor:           p1TestActor,
	})
	if err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}
	if up.Priority != domain.PriorityP1 {
		t.Fatalf("overridden priority = %s, want P1", up.Priority)
	}

	// Created at the upgrade instant.
	assertClockAt(t, pool, sig.ID, domain.SLATargetNotification, upgradeAt, upgradeAt.Add(5*time.Minute))
	assertClockAt(t, pool, sig.ID, domain.SLATargetDecision, upgradeAt, upgradeAt.Add(4*time.Hour))
	// Tightened, started_at preserved at the original commit instant.
	assertClockAt(t, pool, sig.ID, domain.SLATargetAcknowledgement, at, upgradeAt.Add(15*time.Minute))
	assertClockAt(t, pool, sig.ID, domain.SLATargetAssessment, at, upgradeAt.Add(60*time.Minute))

	createdAudits, tightenedAudits := countClockAudits(t, pool, sig.ID)
	if createdAudits != 2 || tightenedAudits != 2 {
		t.Fatalf("clock audits = %d created / %d tightened, want 2 / 2", createdAudits, tightenedAudits)
	}
}
