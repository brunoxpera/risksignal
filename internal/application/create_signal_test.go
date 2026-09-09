package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

const (
	testMatchID = "11111111-1111-1111-1111-111111111111"
	testCveID   = "CVE-2024-0001"
)

// p1Factors is a factor set the ch. 9.3 rules resolve to P1: high
// confidence (exact_identifier, ADR-015), actively exploited (KEV) and a
// critical, internet-exposed asset.
func p1Factors() domain.PriorityFactors {
	return domain.PriorityFactors{
		Method:      domain.MatchMethodExactIdentifier,
		Confidence:  domain.ConfidenceHigh,
		KEV:         true,
		CVSS:        9.8,
		EPSS:        0.99,
		Criticality: domain.CriticalityCritical,
		Exposure:    domain.ExposureInternet,
	}
}

func validInput() application.CreateSignalInput {
	return application.CreateSignalInput{
		MatchID: testMatchID,
		CveID:   testCveID,
		Factors: p1Factors(),
		Actor:   systemActor("synthetic-source"),
	}
}

// TestCreateSignalThreeWritesInOneTransaction is the happy path of the
// ch. 5.1 invariant (ARCH-001 §2): one transaction performs exactly three
// writes — signal, audit event, outbox event — in that order, with the
// documented outbox payload and dedupe key, and commits them together.
func TestCreateSignalThreeWritesInOneTransaction(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	res, err := h.svc.CreateSignal(ctx, validInput())
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}

	// One transaction was opened, committed, and recorded the three writes
	// in order.
	tx := h.runner.last()
	if tx == nil {
		t.Fatal("no transaction was opened")
	}
	if !tx.committed || tx.rolledBack {
		t.Fatalf("transaction committed=%v rolledBack=%v, want committed", tx.committed, tx.rolledBack)
	}
	if want := []string{"signal", "audit", "outbox"}; !equalStrings(tx.log, want) {
		t.Fatalf("write order = %v, want %v", tx.log, want)
	}

	// Exactly one row per table is observable after the commit.
	if got := len(h.db.signalRows); got != 1 {
		t.Fatalf("signal rows = %d, want 1", got)
	}
	if got := len(h.db.auditEvents); got != 1 {
		t.Fatalf("audit rows = %d, want 1", got)
	}
	if got := len(h.db.outboxEvents); got != 1 {
		t.Fatalf("outbox rows = %d, want 1", got)
	}

	// The command returns the stored signal and the correlation id.
	if res.Signal.ID == "" || res.Signal.MatchID != testMatchID {
		t.Fatalf("result signal = %+v, want stored signal for match %s", res.Signal, testMatchID)
	}
	if res.Signal.Priority != domain.PriorityP1 {
		t.Fatalf("priority = %s, want P1 (ch. 9.3)", res.Signal.Priority)
	}
	if res.Signal.Status != domain.SignalStatusNew || res.Signal.Version != 1 {
		t.Fatalf("signal = status %s version %d, want new/1", res.Signal.Status, res.Signal.Version)
	}
	if res.CorrelationID == "" {
		t.Fatal("correlation id is empty, want a generated one")
	}

	// Audit row: the signal.created action of the system actor, linked to
	// the outbox row by the correlation id, with a minimised `after`
	// snapshot and no `before` (a creation, ch. 13.5).
	audit := h.db.auditEvents[0]
	if audit.AggregateType != application.AuditAggregateRiskSignal || audit.AggregateID != res.Signal.ID {
		t.Fatalf("audit aggregate = %s/%s, want risk_signal/%s", audit.AggregateType, audit.AggregateID, res.Signal.ID)
	}
	if audit.Action != application.EventTypeSignalCreated {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalCreated)
	}
	if audit.ActorType != application.ActorTypeSystem || audit.ActorID != "synthetic-source" {
		t.Fatalf("audit actor = %s/%s, want system/synthetic-source", audit.ActorType, audit.ActorID)
	}
	if audit.OccurredAt != fixedNow {
		t.Fatalf("audit occurred_at = %v, want the injected clock time %v", audit.OccurredAt, fixedNow)
	}
	if audit.CorrelationID != res.CorrelationID {
		t.Fatalf("audit correlation_id = %q, want %q", audit.CorrelationID, res.CorrelationID)
	}
	if audit.Before != nil {
		t.Fatalf("audit before = %s, want nil for a creation", audit.Before)
	}
	var after map[string]any
	if err := json.Unmarshal(audit.After, &after); err != nil {
		t.Fatalf("decode audit after: %v", err)
	}
	if after["id"] != res.Signal.ID || after["priority"] != "P1" || after["status"] != "new" {
		t.Fatalf("audit after = %v, want the minimised signal snapshot", after)
	}

	// Outbox row: pending entry of type signal.created with the documented
	// payload and the command-level dedupe key (ARCH-001 §2).
	out := h.db.outboxEvents[0]
	if out.Type != application.EventTypeSignalCreated {
		t.Fatalf("outbox type = %q, want signal.created", out.Type)
	}
	if out.DedupeKey != "signal.created:"+res.Signal.ID {
		t.Fatalf("dedupe key = %q, want %q", out.DedupeKey, "signal.created:"+res.Signal.ID)
	}
	if out.AvailableAt != fixedNow || out.CreatedAt != fixedNow {
		t.Fatalf("outbox timestamps = %v/%v, want the injected clock time", out.AvailableAt, out.CreatedAt)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Payload, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	if payload["type"] != "signal.created" {
		t.Fatalf("payload type = %v, want signal.created", payload["type"])
	}
	if payload["signal_id"] != res.Signal.ID || payload["match_id"] != testMatchID || payload["cve_id"] != testCveID {
		t.Fatalf("payload identities = %v, want signal %s match %s cve %s", payload, res.Signal.ID, testMatchID, testCveID)
	}
	if payload["priority"] != "P1" {
		t.Fatalf("payload priority = %v, want P1", payload["priority"])
	}
	if payload["correlation_id"] != res.CorrelationID {
		t.Fatalf("payload correlation_id = %v, want %q", payload["correlation_id"], res.CorrelationID)
	}
	if payload["event_id"] == "" || payload["event_id"] == nil {
		t.Fatalf("payload event_id = %v, want a generated uuid", payload["event_id"])
	}
	occurredAt, err := time.Parse(time.RFC3339, payload["occurred_at"].(string))
	if err != nil || !occurredAt.Equal(fixedNow) {
		t.Fatalf("payload occurred_at = %v (%v), want %v", payload["occurred_at"], err, fixedNow)
	}
}

// TestCreateSignalCorrelationIDIsRespected keeps a caller-supplied
// correlation id instead of generating one; audit row and outbox payload are
// both linked to it (ARCH-001 §1 audit_events.correlation_id).
func TestCreateSignalCorrelationIDIsRespected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	in := validInput()
	in.CorrelationID = "corr-from-caller"
	res, err := h.svc.CreateSignal(ctx, in)
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	if res.CorrelationID != "corr-from-caller" {
		t.Fatalf("correlation id = %q, want the caller-supplied one", res.CorrelationID)
	}
	if h.db.auditEvents[0].CorrelationID != "corr-from-caller" {
		t.Fatalf("audit correlation_id = %q, want the supplied one", h.db.auditEvents[0].CorrelationID)
	}
	var payload map[string]any
	if err := json.Unmarshal(h.db.outboxEvents[0].Payload, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	if payload["correlation_id"] != "corr-from-caller" {
		t.Fatalf("payload correlation_id = %v, want the supplied one", payload["correlation_id"])
	}
}

// TestCreateSignalOutboxFaultRollsBackEverything is the ARCH-001 §5 fault
// injection: the outbox append fails after the signal and audit writes
// succeeded inside the same transaction. The error propagates unwrapped with
// its ch. 5.2 class, the transaction is rolled back and nothing is
// observable — no signal, no audit event, no outbox row.
func TestCreateSignalOutboxFaultRollsBackEverything(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	cause := errors.New("outbox append failed")
	failpoint := application.InfraError("outbox.append", cause)
	h.outbox.failpoint = failpoint

	_, err := h.svc.CreateSignal(ctx, validInput())
	if err == nil {
		t.Fatal("CreateSignal succeeded, want the injected outbox error")
	}

	// (a) the error propagates unwrapped, preserving the ch. 5.2 class.
	if !errors.Is(err, failpoint) {
		t.Fatalf("error = %v, want the injected error itself (unwrapped)", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error = %v, want the injected cause reachable via errors.Is", err)
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error kind = %s, want infrastructure", kind)
	}

	// (b) the transaction was rolled back, not committed.
	tx := h.runner.last()
	if tx == nil {
		t.Fatal("no transaction was opened")
	}
	if tx.committed {
		t.Fatal("transaction committed despite the outbox failure")
	}
	if !tx.rolledBack {
		t.Fatal("transaction was not rolled back")
	}
	// The three writes were attempted in order before the fault hit.
	if want := []string{"signal", "audit", "outbox"}; !equalStrings(tx.log, want) {
		t.Fatalf("write order = %v, want %v", tx.log, want)
	}

	// (c) no row is observable: the rollback discarded the staged writes.
	if got := len(h.db.signalRows); got != 0 {
		t.Fatalf("signal rows after rollback = %d, want 0", got)
	}
	if got := len(h.db.auditEvents); got != 0 {
		t.Fatalf("audit rows after rollback = %d, want 0", got)
	}
	if got := len(h.db.outboxEvents); got != 0 {
		t.Fatalf("outbox rows after rollback = %d, want 0", got)
	}
}

// TestCreateSignalAuditFaultRollsBackEverything puts the fault one write
// earlier (between state change and audit): the same all-or-nothing holds.
func TestCreateSignalAuditFaultRollsBackEverything(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.audit.failpoint = errors.New("audit append failed")

	_, err := h.svc.CreateSignal(ctx, validInput())
	if err == nil {
		t.Fatal("CreateSignal succeeded, want the injected audit error")
	}
	if len(h.db.signalRows) != 0 || len(h.db.auditEvents) != 0 || len(h.db.outboxEvents) != 0 {
		t.Fatalf("rows observable after rollback: signals=%d audit=%d outbox=%d, want none",
			len(h.db.signalRows), len(h.db.auditEvents), len(h.db.outboxEvents))
	}
}

// TestCreateSignalValidationRejectsBadInput verifies the validation-error
// class of ch. 5.2 and that nothing is written.
func TestCreateSignalValidationRejectsBadInput(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tests := []struct {
		name string
		mut  func(*application.CreateSignalInput)
	}{
		{"empty match id", func(in *application.CreateSignalInput) { in.MatchID = "" }},
		{"empty cve id", func(in *application.CreateSignalInput) { in.CveID = "" }},
		{"non-system actor type", func(in *application.CreateSignalInput) {
			in.Actor = application.Actor{Type: "user", ID: "someone"}
		}},
		{"empty actor id", func(in *application.CreateSignalInput) { in.Actor = systemActor("") }},
		{"factor method without confidence", func(in *application.CreateSignalInput) {
			in.Factors = p1Factors()
			in.Factors.Confidence = domain.ConfidenceMedium // inconsistent with exact_identifier
		}},
		{"cvss out of range", func(in *application.CreateSignalInput) {
			in.Factors = p1Factors()
			in.Factors.CVSS = 11
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInput()
			tt.mut(&in)
			_, err := h.svc.CreateSignal(ctx, in)
			if err == nil {
				t.Fatal("CreateSignal succeeded, want a validation error")
			}
			if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
				t.Fatalf("error kind = %s, want validation", kind)
			}
			if len(h.db.signalRows) != 0 || len(h.db.auditEvents) != 0 || len(h.db.outboxEvents) != 0 {
				t.Fatalf("rows written despite validation error: signals=%d audit=%d outbox=%d",
					len(h.db.signalRows), len(h.db.auditEvents), len(h.db.outboxEvents))
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
