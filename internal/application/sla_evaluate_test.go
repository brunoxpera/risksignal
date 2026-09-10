package application_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file tests the sla.evaluate use case (WP-4.05, ARCH-004 §4.4) against
// the in-memory fakes with the injected FakeClock — the accelerated SLA test:
// an unacknowledged P1 escalates exactly once after its acknowledgement
// deadline (one signal.escalated outbox event + audit), reminders repeat on
// the configured cadence (deduped per cadence window), and P2/P3/P4 never
// escalate.

// outboxRowsOfType returns the committed outbox rows of one event type.
func outboxRowsOfType(h *harness, evtType string) []application.OutboxEvent {
	var out []application.OutboxEvent
	for _, ev := range h.db.outboxEvents {
		if ev.Type == evtType {
			out = append(out, ev)
		}
	}
	return out
}

// TestEvaluateSlaEscalatesUnacknowledgedP1ExactlyOnce is the core accelerated
// SLA proof: a P1 signal whose acknowledgement clock passed its deadline
// escalates exactly once (escalated_at set, one signal.escalated event + one
// audit row) and a re-run writes nothing more.
func TestEvaluateSlaEscalatesUnacknowledgedP1ExactlyOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	sig := domain.RiskSignal{
		ID: "sig-p1", MatchID: testMatchID, Priority: domain.PriorityP1,
		Status: domain.SignalStatusNew, Version: 1, RuleVersion: "p0000000001", Factors: p1Factors(),
	}
	seedStoredSignal(h, sig)
	deadline := fixedNow.Add(15 * time.Minute)
	seedClock(h, sig.ID, domain.SLATargetAcknowledgement, deadline)

	// Before the deadline: nothing is due.
	if res, err := h.svc.EvaluateSla(ctx); err != nil || res.Escalated != 0 {
		t.Fatalf("evaluate before deadline = %+v (err %v), want no escalation", res, err)
	}

	// Past the deadline: the P1 escalates once.
	at := deadline.Add(time.Minute)
	h.clock.Set(at)
	res, err := h.svc.EvaluateSla(ctx)
	if err != nil {
		t.Fatalf("EvaluateSla: %v", err)
	}
	if res.Due != 1 || res.Escalated != 1 || res.Reminders != 0 {
		t.Fatalf("evaluate = %+v, want 1 due / 1 escalated / 0 reminders", res)
	}

	if n := len(outboxRowsOfType(h, application.EventTypeSignalEscalated)); n != 1 {
		t.Fatalf("signal.escalated events = %d, want 1", n)
	}
	if n := countAuditAction(h, application.EventTypeSignalEscalated); n != 1 {
		t.Fatalf("signal.escalated audits = %d, want 1", n)
	}
	row, _ := h.db.signalRowByID(sig.ID)
	if !row.sig.EscalatedAt.Equal(at) {
		t.Fatalf("escalated_at = %v, want %v", row.sig.EscalatedAt, at)
	}
	if row.sig.Version != 2 {
		t.Fatalf("signal version = %d, want 2 (escalation bumped it)", row.sig.Version)
	}

	// The escalation outbox payload names the signal, its priority and target.
	ev := outboxRowsOfType(h, application.EventTypeSignalEscalated)[0]
	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("decode escalation payload: %v", err)
	}
	if payload["signal_id"] != sig.ID || payload["priority"] != "P1" || payload["target"] != "acknowledgement" {
		t.Fatalf("escalation payload = %v, want signal %s / P1 / acknowledgement", payload, sig.ID)
	}

	// A re-run at the same instant is idempotent: no new escalation, no count.
	res2, err := h.svc.EvaluateSla(ctx)
	if err != nil {
		t.Fatalf("EvaluateSla (rerun): %v", err)
	}
	if res2.Escalated != 0 {
		t.Fatalf("rerun escalated %d, want 0 (exactly once)", res2.Escalated)
	}
	if n := len(outboxRowsOfType(h, application.EventTypeSignalEscalated)); n != 1 {
		t.Fatalf("signal.escalated events after rerun = %d, want 1", n)
	}
	if n := countAuditAction(h, application.EventTypeSignalEscalated); n != 1 {
		t.Fatalf("signal.escalated audits after rerun = %d, want 1", n)
	}
}

// TestEvaluateSlaRemindersRepeatOnCadence proves the reminder cadence: after
// the first escalation a reminder is emitted once per cadence window (a
// config value, not table state), a re-run inside a window is deduped, and the
// next window emits a fresh reminder.
func TestEvaluateSlaRemindersRepeatOnCadence(t *testing.T) {
	const cadence = 10 * time.Minute
	h := newHarness(t, func(d *application.ServiceDeps) { d.SLAReminderCadence = cadence })
	ctx := context.Background()

	sig := domain.RiskSignal{
		ID: "sig-remind", MatchID: testMatchID, Priority: domain.PriorityP1,
		Status: domain.SignalStatusNew, Version: 1, RuleVersion: "p0000000001", Factors: p1Factors(),
	}
	seedStoredSignal(h, sig)
	seedClock(h, sig.ID, domain.SLATargetAcknowledgement, fixedNow.Add(15*time.Minute))

	// Escalate.
	h.clock.Set(fixedNow.Add(16 * time.Minute)) // t0
	res, err := h.svc.EvaluateSla(ctx)
	if err != nil {
		t.Fatalf("EvaluateSla (escalate): %v", err)
	}
	if res.Escalated != 1 || res.Reminders != 0 {
		t.Fatalf("evaluate = %+v, want 1 escalated / 0 reminders", res)
	}
	escalatedAt := h.clock.Now()

	// Inside the first cadence window: no reminder yet.
	h.clock.Set(escalatedAt.Add(cadence - time.Second))
	if res, err = h.svc.EvaluateSla(ctx); err != nil || res.Reminders != 0 {
		t.Fatalf("evaluate before cadence = %+v (err %v), want no reminder", res, err)
	}

	// First window elapsed: one reminder.
	h.clock.Set(escalatedAt.Add(cadence))
	res, err = h.svc.EvaluateSla(ctx)
	if err != nil {
		t.Fatalf("EvaluateSla (reminder 1): %v", err)
	}
	if res.Reminders != 1 {
		t.Fatalf("reminders = %d, want 1", res.Reminders)
	}
	// A re-run in the same window is deduped.
	if res, err = h.svc.EvaluateSla(ctx); err != nil || res.Reminders != 0 {
		t.Fatalf("rerun in window = %+v (err %v), want a deduped no-op", res, err)
	}

	// Second window elapsed: a fresh reminder.
	h.clock.Set(escalatedAt.Add(2 * cadence))
	res, err = h.svc.EvaluateSla(ctx)
	if err != nil {
		t.Fatalf("EvaluateSla (reminder 2): %v", err)
	}
	if res.Reminders != 1 {
		t.Fatalf("reminders = %d, want 1 (the second window)", res.Reminders)
	}

	if n := len(outboxRowsOfType(h, application.EventTypeSignalReminder)); n != 2 {
		t.Fatalf("reminder events = %d, want 2 (one per elapsed window)", n)
	}
	if n := countAuditAction(h, application.EventTypeSignalReminder); n != 2 {
		t.Fatalf("reminder audits = %d, want 2 (audited each time)", n)
	}
	// Exactly one escalation, even though the evaluation ran five times.
	if n := len(outboxRowsOfType(h, application.EventTypeSignalEscalated)); n != 1 {
		t.Fatalf("signal.escalated events = %d, want 1", n)
	}
}

// TestEvaluateSlaNeverEscalatesNonP1 proves P2/P3/P4 are never escalated: a
// due acknowledgement clock of a lower-priority signal breaches visibly
// without a signal.escalated event or a reminder.
func TestEvaluateSlaNeverEscalatesNonP1(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for _, p := range []domain.Priority{domain.PriorityP2, domain.PriorityP3, domain.PriorityP4} {
		sig := domain.RiskSignal{
			ID: "sig-" + string(p), MatchID: testMatchID, Priority: p,
			Status: domain.SignalStatusNew, Version: 1, RuleVersion: "p0000000001", Factors: p3Factors(),
		}
		seedStoredSignal(h, sig)
		seedClock(h, sig.ID, domain.SLATargetAcknowledgement, fixedNow.Add(time.Hour))
	}

	h.clock.Set(fixedNow.Add(2 * time.Hour))
	res, err := h.svc.EvaluateSla(ctx)
	if err != nil {
		t.Fatalf("EvaluateSla: %v", err)
	}
	if res.Due != 3 {
		t.Fatalf("due clocks = %d, want 3", res.Due)
	}
	if res.Escalated != 0 || res.Reminders != 0 {
		t.Fatalf("evaluate = %+v, want no escalation/reminder for P2/P3/P4", res)
	}
	if n := len(outboxRowsOfType(h, application.EventTypeSignalEscalated)); n != 0 {
		t.Fatalf("signal.escalated events = %d, want 0", n)
	}
	if n := len(outboxRowsOfType(h, application.EventTypeSignalReminder)); n != 0 {
		t.Fatalf("reminder events = %d, want 0", n)
	}
}

// TestEvaluateSlaSkipsNonAcknowledgementClocks proves the breach scan keys on
// the acknowledgement target only: an overdue assessment clock does not
// escalate its P1 signal (ARCH-004 §4.4).
func TestEvaluateSlaSkipsNonAcknowledgementClocks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	sig := domain.RiskSignal{
		ID: "sig-p1-assess", MatchID: testMatchID, Priority: domain.PriorityP1,
		Status: domain.SignalStatusNew, Version: 1, RuleVersion: "p0000000001", Factors: p1Factors(),
	}
	seedStoredSignal(h, sig)
	seedClock(h, sig.ID, domain.SLATargetAssessment, fixedNow.Add(30*time.Minute))

	h.clock.Set(fixedNow.Add(time.Hour))
	res, err := h.svc.EvaluateSla(ctx)
	if err != nil {
		t.Fatalf("EvaluateSla: %v", err)
	}
	if res.Due != 0 || res.Escalated != 0 {
		t.Fatalf("evaluate = %+v, want the assessment clock ignored", res)
	}
}
