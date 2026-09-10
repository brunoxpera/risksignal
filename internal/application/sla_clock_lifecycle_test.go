package application_test

// DEV-079 — the ARCH-004 §4.3 clock lifecycle at the application layer:
// Create creates every clock the signal's priority defines, and a priority
// upgrade (manual override) creates the missing clocks and tightens the
// existing ones — never lengthening a deadline. The clock treatment runs on
// the command's own transaction, so a fault rolls it back with the command
// (fault seam, TR-004).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// p4Factors is a factor set the ch. 9.3 rules resolve to P4: a low-confidence
// candidate assignment (no confirmed inventory impact). The P4 profile defines
// only the weekly-review assessment clock.
func p4Factors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method:      domain.MatchMethodCandidate,
		Confidence:  domain.ConfidenceLow,
		KEV:         false,
		CVSS:        3.0,
		EPSS:        0.01,
		Criticality: domain.CriticalityLow,
		Exposure:    domain.ExposureInternal,
	}
}

// seedSignalWithFactors creates one committed signal for the given factor set
// through the CreateSignal command (the read/load the triage commands start
// from), so the assertions observe the clocks the create path actually wrote.
func seedSignalWithFactors(t *testing.T, h *harness, factors domain.PriorityFactors) domain.RiskSignal {
	t.Helper()
	res, err := h.svc.CreateSignal(context.Background(), application.CreateSignalInput{
		MatchID: testMatchID,
		CveID:   testCveID,
		Factors: factors,
		Actor:   systemActor("demo-seed"),
	})
	if err != nil {
		t.Fatalf("seed CreateSignal: %v", err)
	}
	return res.Signal
}

// assertClocksAt asserts the signal carries exactly the expected open clocks —
// one per target, started at the given instant with the target's deadline —
// and no other target's clock.
func assertClocksAt(t *testing.T, h *harness, signalID string, start time.Time, want map[domain.SLATarget]time.Duration) {
	t.Helper()
	if got := len(h.db.slaClocks); got != len(want) {
		t.Fatalf("sla clocks = %d, want the %d defined clocks", got, len(want))
	}
	for target, d := range want {
		clock, ok := h.db.slaClockByKey(signalID, target)
		if !ok {
			t.Fatalf("%s clock missing", target)
		}
		if !clock.StartedAt.Equal(start) || !clock.DeadlineAt.Equal(start.Add(d)) {
			t.Fatalf("%s clock = started %v deadline %v, want %v / %v", target, clock.StartedAt, clock.DeadlineAt, start, start.Add(d))
		}
		if clock.Fulfilled() {
			t.Fatalf("%s clock = %+v, want open", target, clock)
		}
	}
}

// p1Durations is the ch. 9.4 P1 profile (all four clocks).
func p1Durations() map[domain.SLATarget]time.Duration {
	return map[domain.SLATarget]time.Duration{
		domain.SLATargetNotification:    5 * time.Minute,
		domain.SLATargetAcknowledgement: 15 * time.Minute,
		domain.SLATargetAssessment:      60 * time.Minute,
		domain.SLATargetDecision:        4 * time.Hour,
	}
}

// TestCreateSignalP1CreatesAllFourClocks proves the Create path creates every
// clock the P1 profile defines, at the commit instant (ARCH-004 §4.3 Create).
func TestCreateSignalP1CreatesAllFourClocks(t *testing.T) {
	h := newHarness(t)
	sig := seedSignalWithFactors(t, h, p1Factors())
	if sig.Priority != domain.PriorityP1 {
		t.Fatalf("priority = %s, want P1", sig.Priority)
	}
	assertClocksAt(t, h, sig.ID, fixedNow, p1Durations())
}

// TestCreateSignalP3OmitsNotificationAndDecision proves the Create path
// creates only the targets the priority defines: P3 has no notification
// (no paging) and no decision clock (ch. 9.4), only acknowledgement +
// assessment.
func TestCreateSignalP3OmitsNotificationAndDecision(t *testing.T) {
	h := newHarness(t)
	sig := seedSignalWithFactors(t, h, p3Factors())
	if sig.Priority != domain.PriorityP3 {
		t.Fatalf("priority = %s, want P3", sig.Priority)
	}
	assertClocksAt(t, h, sig.ID, fixedNow, map[domain.SLATarget]time.Duration{
		domain.SLATargetAcknowledgement: 24 * time.Hour,
		domain.SLATargetAssessment:      72 * time.Hour,
	})
	for _, absent := range []domain.SLATarget{domain.SLATargetNotification, domain.SLATargetDecision} {
		if _, ok := h.db.slaClockByKey(sig.ID, absent); ok {
			t.Fatalf("%s clock exists, want none (P3 does not define it)", absent)
		}
	}
}

// TestOverrideUpgradeCreatesMissingAndTightensExisting is the ARCH-004 §4.3
// upgrade: a P3→P1 override creates the missing notification + decision
// clocks from the upgrade instant, tightens acknowledgement + assessment to
// the new deadline (keeping started_at) and audits every mutation with the
// old→new deadline on the tighten.
func TestOverrideUpgradeCreatesMissingAndTightensExisting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignalWithFactors(t, h, p3Factors()) // ack 24h, assessment 72h at fixedNow

	// The upgrade happens half an hour after the commit.
	const delta = 30 * time.Minute
	h.clock.Advance(delta)
	upgradeAt := fixedNow.Add(delta)

	up, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP1, Reason: "KEV added", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}
	if up.Priority != domain.PriorityP1 {
		t.Fatalf("priority = %s, want P1", up.Priority)
	}

	// All four P1 clocks now exist with the new deadlines.
	for target, d := range p1Durations() {
		clock, ok := h.db.slaClockByKey(sig.ID, target)
		if !ok {
			t.Fatalf("%s clock missing after the upgrade", target)
		}
		if !clock.DeadlineAt.Equal(upgradeAt.Add(d)) {
			t.Fatalf("%s deadline = %v, want %v (now + duration)", target, clock.DeadlineAt, upgradeAt.Add(d))
		}
		if clock.Fulfilled() {
			t.Fatalf("%s clock = %+v, want open", target, clock)
		}
	}
	// The created clocks start at the upgrade instant …
	for _, created := range []domain.SLATarget{domain.SLATargetNotification, domain.SLATargetDecision} {
		clock, _ := h.db.slaClockByKey(sig.ID, created)
		if !clock.StartedAt.Equal(upgradeAt) {
			t.Fatalf("%s started_at = %v, want the upgrade instant %v", created, clock.StartedAt, upgradeAt)
		}
	}
	// … the tightened clocks keep their original started_at.
	for _, tightened := range []domain.SLATarget{domain.SLATargetAcknowledgement, domain.SLATargetAssessment} {
		clock, _ := h.db.slaClockByKey(sig.ID, tightened)
		if !clock.StartedAt.Equal(fixedNow) {
			t.Fatalf("%s started_at = %v, want the original commit instant %v (kept on tighten)", tightened, clock.StartedAt, fixedNow)
		}
	}

	// Every mutation is audited: two creations and two tightenings, the
	// tighten carrying the old→new deadline (ARCH-004 §4.3, ch. 9.4).
	assertClockAudits(t, h, 2, 2)
	assertTightenAudit(t, h, domain.SLATargetAcknowledgement, fixedNow.Add(24*time.Hour), upgradeAt.Add(15*time.Minute))
	assertTightenAudit(t, h, domain.SLATargetAssessment, fixedNow.Add(72*time.Hour), upgradeAt.Add(60*time.Minute))
}

// TestOverrideDowngradeDoesNotLengthen proves a P1→P3 override never lengthens
// a deadline: the P3 targets already have earlier deadlines, so neither is
// tightened, and the P3-undefined notification/decision clocks are left
// untouched (no clock mutation, no clock audit).
func TestOverrideDowngradeDoesNotLengthen(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignalWithFactors(t, h, p1Factors()) // all four clocks at fixedNow

	before := len(h.db.auditEvents)
	h.clock.Advance(30 * time.Minute)
	up, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP3, Reason: "asset decommissioned", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}
	if up.Priority != domain.PriorityP3 {
		t.Fatalf("priority = %s, want P3", up.Priority)
	}

	// Every clock keeps its original deadline and started_at; the P3-absent
	// notification/decision clocks survive untouched.
	assertClocksAt(t, h, sig.ID, fixedNow, p1Durations())

	// Only the override's own audit was written — no clock mutation happened.
	if got := len(h.db.auditEvents) - before; got != 1 {
		t.Fatalf("audit rows added by the downgrade = %d, want 1 (the override only)", got)
	}
	if h.db.auditEvents[len(h.db.auditEvents)-1].Action != application.EventTypeSignalPriorityOverridden {
		t.Fatalf("last audit action = %q, want %q", h.db.auditEvents[len(h.db.auditEvents)-1].Action, application.EventTypeSignalPriorityOverridden)
	}
}

// TestOverrideNeverTightensFulfilledClock proves a fulfilled clock is left
// untouched by a priority upgrade (ARCH-004 §4.3): its target is already met,
// so its deadline is neither shortened nor re-opened, while the signal's
// other unfulfilled clocks are tightened and its missing clocks created.
func TestOverrideNeverTightensFulfilledClock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignalWithFactors(t, h, p3Factors()) // ack 24h, assessment 72h at fixedNow

	// Acknowledge half an hour in: the acknowledgement clock is fulfilled and
	// the signal moves to in_review.
	const delta = 30 * time.Minute
	h.clock.Advance(delta)
	ackAt := fixedNow.Add(delta)
	acked, err := h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("AcknowledgeSignal: %v", err)
	}

	// Upgrade to P1: it must not touch the fulfilled acknowledgement clock.
	if _, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP1, Reason: "KEV added", ExpectedVersion: acked.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}

	// The fulfilled acknowledgement clock kept its deadline and started_at.
	ack, ok := h.db.slaClockByKey(sig.ID, domain.SLATargetAcknowledgement)
	if !ok || !ack.Fulfilled() || !ack.FulfilledAt.Equal(ackAt) {
		t.Fatalf("acknowledgement clock = %+v (ok=%v), want fulfilled at %v", ack, ok, ackAt)
	}
	if !ack.StartedAt.Equal(fixedNow) || !ack.DeadlineAt.Equal(fixedNow.Add(24*time.Hour)) {
		t.Fatalf("fulfilled acknowledgement clock = started %v deadline %v, want the untouched %v / %v",
			ack.StartedAt, ack.DeadlineAt, fixedNow, fixedNow.Add(24*time.Hour))
	}
	// The unfulfilled assessment clock is tightened to the P1 deadline.
	assess, _ := h.db.slaClockByKey(sig.ID, domain.SLATargetAssessment)
	if !assess.StartedAt.Equal(fixedNow) || !assess.DeadlineAt.Equal(ackAt.Add(60*time.Minute)) {
		t.Fatalf("assessment clock = %+v, want started %v tightened to %v", assess, fixedNow, ackAt.Add(60*time.Minute))
	}
	// The missing P1 clocks are created; exactly one tighten (assessment) and
	// two creates (notification, decision) are audited.
	assertClockAudits(t, h, 2, 1)
}

// TestUpgradeOutboxFaultRollsBackClockTreatment arms the outbox fault seam of
// the override: the failing append rolls the override — and the clock creates
// and tightens it staged — back with it. No half-state (TR-004).
func TestUpgradeOutboxFaultRollsBackClockTreatment(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignalWithFactors(t, h, p3Factors()) // ack 24h, assessment 72h

	h.clock.Advance(30 * time.Minute)
	h.outbox.failpoint = application.InfraError("outbox.append", errors.New("outbox append failed"))

	if _, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP1, Reason: "KEV added", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("OverridePriority succeeded despite the injected outbox error")
	}

	// The clocks are exactly the two the create wrote at their original
	// deadlines: the upgrade's create/tighten rolled back.
	assertClocksAt(t, h, sig.ID, fixedNow, map[domain.SLATarget]time.Duration{
		domain.SLATargetAcknowledgement: 24 * time.Hour,
		domain.SLATargetAssessment:      72 * time.Hour,
	})
	// The override itself rolled back: the signal is still P3 and no extra
	// audit row survived.
	row, ok := h.db.signalRowByID(sig.ID)
	if !ok || row.sig.Priority != domain.PriorityP3 {
		t.Fatalf("signal priority after rollback = %s (ok=%v), want the unchanged P3", row.sig.Priority, ok)
	}
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit rows after rollback = %d, want only the seed's create audit", len(h.db.auditEvents))
	}
}

// assertClockAudits asserts the committed audit log holds exactly wantCreated
// clock-created and wantTightened clock-tightened events.
func assertClockAudits(t *testing.T, h *harness, wantCreated, wantTightened int) {
	t.Helper()
	var created, tightened int
	for _, ev := range h.db.auditEvents {
		switch ev.Action {
		case application.EventTypeSignalSLAClockCreated:
			created++
		case application.EventTypeSignalSLAClockTightened:
			tightened++
		}
	}
	if created != wantCreated || tightened != wantTightened {
		t.Fatalf("clock audits = %d created / %d tightened, want %d / %d", created, tightened, wantCreated, wantTightened)
	}
}

// assertTightenAudit asserts the tighten audit of one target recorded the
// expected old→new deadline (ch. 9.4 "bereits verstrichene Bearbeitungszeit
// bleibt sichtbar").
func assertTightenAudit(t *testing.T, h *harness, target domain.SLATarget, oldDeadline, newDeadline time.Time) {
	t.Helper()
	for _, ev := range h.db.auditEvents {
		if ev.Action != application.EventTypeSignalSLAClockTightened {
			continue
		}
		var snap struct {
			Target      string    `json:"target"`
			DeadlineAt  time.Time `json:"deadline_at"`
			OldDeadline time.Time `json:"old_deadline_at"`
		}
		if err := json.Unmarshal(ev.After, &snap); err != nil {
			t.Fatalf("decode tighten audit: %v", err)
		}
		if snap.Target != string(target) {
			continue
		}
		if !snap.OldDeadline.Equal(oldDeadline) || !snap.DeadlineAt.Equal(newDeadline) {
			t.Fatalf("%s tighten audit = old %v new %v, want old %v new %v", target, snap.OldDeadline, snap.DeadlineAt, oldDeadline, newDeadline)
		}
		return
	}
	t.Fatalf("no tighten audit found for %s", target)
}
