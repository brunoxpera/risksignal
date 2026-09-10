package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// seedSignal creates one committed signal through the CreateSignal command —
// the read/load the I4 triage commands start from.
func seedSignal(t *testing.T, h *harness) domain.RiskSignal {
	t.Helper()
	res, err := h.svc.CreateSignal(context.Background(), application.CreateSignalInput{
		MatchID: testMatchID,
		CveID:   testCveID,
		Factors: p1Factors(),
		Actor:   systemActor("demo-seed"),
	})
	if err != nil {
		t.Fatalf("seed CreateSignal: %v", err)
	}
	return res.Signal
}

// TestTransitionSignalWritesStateAuditOutbox is the happy path of the I4
// command shape: one transaction performs the guarded status change, the
// audit event and the outbox event, in that order, and commits them together.
func TestTransitionSignalWritesStateAuditOutbox(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)

	updated, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID:        sig.ID,
		To:              domain.SignalStatusActionPlanned,
		ExpectedVersion: sig.Version,
		Actor:           systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("TransitionSignal: %v", err)
	}
	if updated.Status != domain.SignalStatusActionPlanned || updated.Version != sig.Version+1 {
		t.Fatalf("updated = status %s version %d, want action_planned/%d", updated.Status, updated.Version, sig.Version+1)
	}

	// One command, one transaction; state → audit → SLA clocks → outbox on
	// it (the clock treatment of the transition commits with the rest).
	tx := h.runner.last()
	if tx == nil || !tx.committed || tx.rolledBack {
		t.Fatalf("transaction committed=%v rolledBack=%v, want a committed one", tx.committed, tx.rolledBack)
	}
	// The P1 signal fulfils assessment + decision on → action_planned; both
	// clocks are missing here, so each fulfil is a recorded no-op.
	if want := []string{"signal.transition", "audit", "sla.fulfil", "sla.fulfil", "outbox"}; !equalStrings(tx.log, want) {
		t.Fatalf("write order = %v, want %v", tx.log, want)
	}

	// The committed row carries the new status.
	row, ok := h.db.signalRowByID(sig.ID)
	if !ok || row.sig.Status != domain.SignalStatusActionPlanned {
		t.Fatalf("committed signal = %+v (ok=%v), want action_planned", row.sig, ok)
	}

	// The audit event records the before/after snapshots and the actor.
	audit := h.db.auditEvents[len(h.db.auditEvents)-1]
	if audit.Action != application.EventTypeSignalTransitioned {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalTransitioned)
	}
	if audit.AggregateID != sig.ID || audit.ActorID != "analyst" {
		t.Fatalf("audit aggregate/actor = %s/%s, want %s/analyst", audit.AggregateID, audit.ActorID, sig.ID)
	}
	if len(audit.Before) == 0 || len(audit.After) == 0 {
		t.Fatalf("audit before/after = %s/%s, want both snapshots", audit.Before, audit.After)
	}
	var before, after map[string]any
	if err := json.Unmarshal(audit.Before, &before); err != nil {
		t.Fatalf("decode before: %v", err)
	}
	if err := json.Unmarshal(audit.After, &after); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	if before["status"] != "new" || after["status"] != "action_planned" {
		t.Fatalf("snapshots = before %v / after %v, want new/action_planned", before, after)
	}

	// The outbox event carries the envelope and the from/to identities.
	out := h.db.outboxEvents[len(h.db.outboxEvents)-1]
	if out.Type != application.EventTypeSignalTransitioned {
		t.Fatalf("outbox type = %q, want %q", out.Type, application.EventTypeSignalTransitioned)
	}
	if out.DedupeKey == "" || out.DedupeKey[:len(application.EventTypeSignalTransitioned)+1] != application.EventTypeSignalTransitioned+":" {
		t.Fatalf("dedupe key = %q, want the %q namespace", out.DedupeKey, application.EventTypeSignalTransitioned)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Payload, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	if payload["signal_id"] != sig.ID || payload["from"] != "new" || payload["to"] != "action_planned" {
		t.Fatalf("outbox payload = %v, want signal %s new->action_planned", payload, sig.ID)
	}
	if audit.CorrelationID != payload["correlation_id"] {
		t.Fatalf("audit/outbox correlation ids differ: %q vs %v", audit.CorrelationID, payload["correlation_id"])
	}
}

// TestTransitionSignalOffMatrixIsConflict rejects an off-matrix edge with the
// conflict class (TR-001) and writes nothing.
func TestTransitionSignalOffMatrixIsConflict(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	audits, outbox := len(h.db.auditEvents), len(h.db.outboxEvents)

	tests := []struct {
		name string
		to   domain.SignalStatus
	}{
		{"new cannot resolve directly", domain.SignalStatusResolved},
		{"no self-transition", domain.SignalStatusNew},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
				SignalID: sig.ID, To: tt.to, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
			})
			if err == nil {
				t.Fatal("TransitionSignal succeeded, want a conflict")
			}
			if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
				t.Fatalf("error kind = %s, want conflict", kind)
			}
		})
	}
	if len(h.db.auditEvents) != audits || len(h.db.outboxEvents) != outbox {
		t.Fatalf("rows written on a rejected transition: audit=%d outbox=%d", len(h.db.auditEvents), len(h.db.outboxEvents))
	}
}

// TestTransitionSignalRequiresReasonForClosedEntry enforces the mandatory
// reason of the closed-entry edge (ch. 6.3): blank is a validation error, a
// present reason transitions and stamps closed_at.
func TestTransitionSignalRequiresReasonForClosedEntry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)

	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusNotAffected, Reason: "  ", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("TransitionSignal accepted a blank reason for a closed entry")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}

	updated, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusNotAffected, Reason: "no affected asset", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("TransitionSignal with reason: %v", err)
	}
	if updated.Status != domain.SignalStatusNotAffected {
		t.Fatalf("status = %s, want not_affected", updated.Status)
	}
	row, _ := h.db.signalRowByID(sig.ID)
	if row.closedAt == nil || !row.closedAt.Equal(fixedNow) {
		t.Fatalf("closed_at = %v, want the injected clock instant %v", row.closedAt, fixedNow)
	}
}

// TestTransitionSignalReopenClearsClosedAt drives a signal into a closed state
// and reopens it with a mandatory reason: the reopen clears closed_at (the
// retention countdown stops, ch. 6.3).
func TestTransitionSignalReopenClearsClosedAt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	// A P1 signal defines all four clocks; the reopen resets each, so the
	// fixture seeds them (a reset of a missing defined clock is an
	// inconsistency and would fail the command).
	for _, target := range []domain.SLATarget{
		domain.SLATargetNotification, domain.SLATargetAcknowledgement,
		domain.SLATargetAssessment, domain.SLATargetDecision,
	} {
		seedClock(h, sig.ID, target, fixedNow.Add(24*time.Hour))
	}

	planned, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("-> action_planned: %v", err)
	}
	resolved, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusResolved, Reason: "patching verified", ExpectedVersion: planned.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("-> resolved: %v", err)
	}
	if row, _ := h.db.signalRowByID(sig.ID); row.closedAt == nil {
		t.Fatal("closed_at not set on entry into resolved")
	}

	// A reopen without a reason is rejected, with a reason it clears
	// closed_at.
	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusInReview, ExpectedVersion: resolved.Version, Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("reopen without a reason was accepted")
	}
	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusInReview, Reason: "new evidence", ExpectedVersion: resolved.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if row, _ := h.db.signalRowByID(sig.ID); row.closedAt != nil {
		t.Fatalf("closed_at = %v after reopen, want nil", row.closedAt)
	}
}

// TestTransitionSignalStaleVersionIsConflict rejects a stale optimistic-lock
// version (ch. 7.3) without writing.
func TestTransitionSignalStaleVersionIsConflict(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)

	_, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version + 5, Actor: systemActor("analyst"),
	})
	if err == nil {
		t.Fatal("TransitionSignal succeeded with a stale version")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("error kind = %s, want conflict", kind)
	}
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit rows = %d, want only the create row", len(h.db.auditEvents))
	}
}

// TestTransitionSignalMissingSignalIsNotFound surfaces an unknown id as a
// not-found error.
func TestTransitionSignalMissingSignalIsNotFound(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.TransitionSignal(context.Background(), application.TransitionSignalInput{
		SignalID: "does-not-exist", To: domain.SignalStatusActionPlanned, ExpectedVersion: 1, Actor: systemActor("analyst"),
	})
	if err == nil {
		t.Fatal("TransitionSignal succeeded for an unknown signal")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("error kind = %s, want not_found", kind)
	}
}

// TestAssignOwner sets and clears the owner under the optimistic lock.
func TestAssignOwner(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)

	assigned, err := h.svc.AssignOwner(ctx, application.AssignOwnerInput{
		SignalID: sig.ID, Owner: "user-42", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("AssignOwner: %v", err)
	}
	if assigned.Owner != "user-42" || assigned.Version != sig.Version+1 {
		t.Fatalf("assigned = owner %q version %d, want user-42/%d", assigned.Owner, assigned.Version, sig.Version+1)
	}
	if audit := h.db.auditEvents[len(h.db.auditEvents)-1]; audit.Action != application.EventTypeSignalOwnerAssigned {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalOwnerAssigned)
	}
	if out := h.db.outboxEvents[len(h.db.outboxEvents)-1]; out.Type != application.EventTypeSignalOwnerAssigned {
		t.Fatalf("outbox type = %q, want %q", out.Type, application.EventTypeSignalOwnerAssigned)
	}

	cleared, err := h.svc.AssignOwner(ctx, application.AssignOwnerInput{
		SignalID: sig.ID, Owner: "", ExpectedVersion: assigned.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("AssignOwner(clear): %v", err)
	}
	if cleared.Owner != "" {
		t.Fatalf("owner = %q, want cleared", cleared.Owner)
	}
}

// TestAddComment appends an immutable comment and rejects a blank body.
func TestAddComment(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)

	if _, err := h.svc.AddComment(ctx, application.AddCommentInput{
		SignalID: sig.ID, Body: "   ", Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("AddComment accepted a blank body")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}

	comment, err := h.svc.AddComment(ctx, application.AddCommentInput{
		SignalID: sig.ID, Body: "triaged, escalating", Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if comment.ID == "" || comment.SignalID != sig.ID || comment.ActorID != "analyst" {
		t.Fatalf("comment = %+v, want a stored comment of %s by analyst", comment, sig.ID)
	}
	audit := h.db.auditEvents[len(h.db.auditEvents)-1]
	if audit.Action != application.EventTypeSignalCommented {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalCommented)
	}
	if audit.Before != nil {
		t.Fatalf("audit before = %s, want nil for an append", audit.Before)
	}
	// The comment body never enters the audit snapshot.
	if len(audit.After) == 0 || strings.Contains(string(audit.After), "escalating") {
		t.Fatalf("audit after = %s, want a minimised snapshot without the body", audit.After)
	}
	if out := h.db.outboxEvents[len(h.db.outboxEvents)-1]; out.Type != application.EventTypeSignalCommented {
		t.Fatalf("outbox type = %q, want %q", out.Type, application.EventTypeSignalCommented)
	}
}

// TestAcknowledgeSignal acknowledges a new signal (new → in_review) and
// rejects a second acknowledgement (in_review → in_review is off-matrix).
func TestAcknowledgeSignal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)

	acked, err := h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("AcknowledgeSignal: %v", err)
	}
	if acked.Status != domain.SignalStatusInReview {
		t.Fatalf("status = %s, want in_review", acked.Status)
	}
	if audit := h.db.auditEvents[len(h.db.auditEvents)-1]; audit.Action != application.EventTypeSignalAcknowledged {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalAcknowledged)
	}

	if _, err := h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: acked.Version, Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("second acknowledgement succeeded, want a conflict")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("error kind = %s, want conflict", kind)
	}
}

// TestOverrideRevertPriorityRoundTrip verifies the ADR-015 mirror: an override
// preserves the computed value in auto_priority and records the
// reason/actor/time; a revert restores it and clears the override columns.
func TestOverrideRevertPriorityRoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h) // computed P1
	computed := sig.Priority

	overridden, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP3, Reason: "asset decommissioned", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}
	if overridden.Priority != domain.PriorityP3 {
		t.Fatalf("priority = %s, want P3", overridden.Priority)
	}
	if overridden.AutoPriority == nil || *overridden.AutoPriority != computed {
		t.Fatalf("auto_priority = %v, want the computed %s", overridden.AutoPriority, computed)
	}
	if overridden.OverrideReason != "asset decommissioned" || overridden.OverrideActorID != "analyst" || !overridden.OverrideAt.Equal(fixedNow) {
		t.Fatalf("override stamps = %q/%q/%v", overridden.OverrideReason, overridden.OverrideActorID, overridden.OverrideAt)
	}
	if audit := h.db.auditEvents[len(h.db.auditEvents)-1]; audit.Action != application.EventTypeSignalPriorityOverridden {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalPriorityOverridden)
	}

	// A second override without a revert is a validation error.
	if _, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP2, Reason: "again", ExpectedVersion: overridden.Version, Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("second override without revert was accepted")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}

	reverted, err := h.svc.RevertPriority(ctx, application.RevertPriorityInput{
		SignalID: sig.ID, ExpectedVersion: overridden.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("RevertPriority: %v", err)
	}
	if reverted.Priority != computed || reverted.AutoPriority != nil {
		t.Fatalf("reverted = priority %s auto %v, want %s/nil", reverted.Priority, reverted.AutoPriority, computed)
	}
	if reverted.OverrideReason != "" || reverted.OverrideActorID != "" || !reverted.OverrideAt.IsZero() {
		t.Fatalf("override columns not cleared: %q/%q/%v", reverted.OverrideReason, reverted.OverrideActorID, reverted.OverrideAt)
	}
	if audit := h.db.auditEvents[len(h.db.auditEvents)-1]; audit.Action != application.EventTypeSignalPriorityReverted {
		t.Fatalf("audit action = %q, want %q", audit.Action, application.EventTypeSignalPriorityReverted)
	}
}

// TestOverrideRequiresReason rejects a blank override reason.
func TestOverrideRequiresReason(t *testing.T) {
	h := newHarness(t)
	sig := seedSignal(t, h)
	if _, err := h.svc.OverridePriority(context.Background(), application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP3, Reason: " ", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("OverridePriority accepted a blank reason")
	}
}

// TestRevertWithoutOverrideIsValidation rejects a revert of a purely computed
// signal.
func TestRevertWithoutOverrideIsValidation(t *testing.T) {
	h := newHarness(t)
	sig := seedSignal(t, h)
	_, err := h.svc.RevertPriority(context.Background(), application.RevertPriorityInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err == nil {
		t.Fatal("RevertPriority accepted a signal without an override")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}
}

// seedClock places one committed SLA clock on the fake store. It upserts by
// natural key, so a target the CreateSignal path already created is replaced
// rather than duplicated — the same natural-key semantics as the repository.
func seedClock(h *harness, signalID string, target domain.SLATarget, deadline time.Time) domain.SlaClock {
	c := domain.SlaClock{
		ID:         "clock-" + string(target),
		SignalID:   signalID,
		Target:     target,
		StartedAt:  fixedNow,
		DeadlineAt: deadline,
	}
	h.db.applySlaClock(c)
	return c
}

// TestPauseResumeAccumulatesPausedSeconds pauses a clock, advances the clock,
// and resumes it: paused_seconds accumulates the elapsed pause (ch. 9.4).
func TestPauseResumeAccumulatesPausedSeconds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	seedClock(h, sig.ID, domain.SLATargetAcknowledgement, fixedNow.Add(15*time.Minute))

	paused, err := h.svc.PauseSla(ctx, application.PauseSlaInput{
		SignalID: sig.ID, Target: domain.SLATargetAcknowledgement, Reason: "awaiting vendor", Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("PauseSla: %v", err)
	}
	if !paused.Paused() || !paused.PausedAt.Equal(fixedNow) {
		t.Fatalf("paused clock = %+v, want paused_at %v", paused, fixedNow)
	}

	// A pause is not retroactive and the remaining time is frozen while
	// paused: the effective deadline slides by the paused span.
	if got := paused.EffectiveDeadline(fixedNow.Add(10 * time.Minute)); !got.Equal(fixedNow.Add(15 * time.Minute).Add(10 * time.Minute)) {
		t.Fatalf("effective deadline while paused = %v, want the frozen deadline", got)
	}

	h.clock.Advance(10 * time.Minute)
	resumed, err := h.svc.ResumeSla(ctx, application.ResumeSlaInput{
		SignalID: sig.ID, Target: domain.SLATargetAcknowledgement, Reason: "vendor answered", Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("ResumeSla: %v", err)
	}
	if resumed.Paused() {
		t.Fatal("clock still paused after resume")
	}
	if want := int64((10 * time.Minute) / time.Second); resumed.PausedSeconds != want {
		t.Fatalf("paused_seconds = %d, want %d", resumed.PausedSeconds, want)
	}

	// Both commands audited + enqueued their event.
	actions := []string{
		h.db.auditEvents[len(h.db.auditEvents)-2].Action,
		h.db.auditEvents[len(h.db.auditEvents)-1].Action,
	}
	if actions[0] != application.EventTypeSignalSLAPaused || actions[1] != application.EventTypeSignalSLAResumed {
		t.Fatalf("SLA audit actions = %v, want paused then resumed", actions)
	}
}

// TestPauseSlaGuards covers the guarded-write conflicts: an already-paused
// clock cannot be paused twice and a running clock cannot be resumed.
func TestPauseSlaGuards(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	seedClock(h, sig.ID, domain.SLATargetAssessment, fixedNow.Add(time.Hour))

	if _, err := h.svc.PauseSla(ctx, application.PauseSlaInput{
		SignalID: sig.ID, Target: domain.SLATargetAssessment, Reason: "hold", Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("first pause: %v", err)
	}
	if _, err := h.svc.PauseSla(ctx, application.PauseSlaInput{
		SignalID: sig.ID, Target: domain.SLATargetAssessment, Reason: "hold again", Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("second pause succeeded")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("error kind = %s, want conflict", kind)
	}
	if _, err := h.svc.ResumeSla(ctx, application.ResumeSlaInput{
		SignalID: sig.ID, Target: domain.SLATargetDecision, Reason: "n/a", Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("resume of a missing clock succeeded")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("error kind = %s, want conflict", kind)
	}
}

// TestTriageActorIDMandatory rejects a command without an actor id.
func TestTriageActorIDMandatory(t *testing.T) {
	h := newHarness(t)
	sig := seedSignal(t, h)
	ctx := context.Background()

	_, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version,
	})
	if err == nil {
		t.Fatal("TransitionSignal accepted an empty actor id")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}
}

// TestEveryTriageCommandEnqueuesOutbox drives the full command surface over
// one signal and asserts that every command enqueues exactly one outbox event
// of its type in the same transaction (the fault seam of the I4 commands).
func TestEveryTriageCommandEnqueuesOutbox(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	seedClock(h, sig.ID, domain.SLATargetNotification, fixedNow.Add(time.Hour))

	analyst := systemActor("analyst")
	expect := func(t *testing.T, before int, evtType string) {
		t.Helper()
		if len(h.db.outboxEvents) != before+1 {
			t.Fatalf("outbox rows = %d, want %d", len(h.db.outboxEvents), before+1)
		}
		if got := h.db.outboxEvents[len(h.db.outboxEvents)-1].Type; got != evtType {
			t.Fatalf("outbox type = %q, want %q", got, evtType)
		}
	}

	n := len(h.db.outboxEvents)
	acked, err := h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: analyst})
	if err != nil {
		t.Fatalf("AcknowledgeSignal: %v", err)
	}
	expect(t, n, application.EventTypeSignalAcknowledged)

	n = len(h.db.outboxEvents)
	planned, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: acked.Version, Actor: analyst})
	if err != nil {
		t.Fatalf("TransitionSignal: %v", err)
	}
	expect(t, n, application.EventTypeSignalTransitioned)

	n = len(h.db.outboxEvents)
	owned, err := h.svc.AssignOwner(ctx, application.AssignOwnerInput{SignalID: sig.ID, Owner: "user-7", ExpectedVersion: planned.Version, Actor: analyst})
	if err != nil {
		t.Fatalf("AssignOwner: %v", err)
	}
	expect(t, n, application.EventTypeSignalOwnerAssigned)

	n = len(h.db.outboxEvents)
	if _, err := h.svc.AddComment(ctx, application.AddCommentInput{SignalID: sig.ID, Body: "note", Actor: analyst}); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	expect(t, n, application.EventTypeSignalCommented)

	n = len(h.db.outboxEvents)
	overridden, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{SignalID: sig.ID, Priority: domain.PriorityP3, Reason: "downgrade", ExpectedVersion: owned.Version, Actor: analyst})
	if err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}
	expect(t, n, application.EventTypeSignalPriorityOverridden)

	n = len(h.db.outboxEvents)
	if _, err := h.svc.RevertPriority(ctx, application.RevertPriorityInput{SignalID: sig.ID, ExpectedVersion: overridden.Version, Actor: analyst}); err != nil {
		t.Fatalf("RevertPriority: %v", err)
	}
	expect(t, n, application.EventTypeSignalPriorityReverted)

	n = len(h.db.outboxEvents)
	if _, err := h.svc.PauseSla(ctx, application.PauseSlaInput{SignalID: sig.ID, Target: domain.SLATargetNotification, Reason: "hold", Actor: analyst}); err != nil {
		t.Fatalf("PauseSla: %v", err)
	}
	expect(t, n, application.EventTypeSignalSLAPaused)

	n = len(h.db.outboxEvents)
	if _, err := h.svc.ResumeSla(ctx, application.ResumeSlaInput{SignalID: sig.ID, Target: domain.SLATargetNotification, Reason: "resume", Actor: analyst}); err != nil {
		t.Fatalf("ResumeSla: %v", err)
	}
	expect(t, n, application.EventTypeSignalSLAResumed)
}

// TestTriageOutboxFaultRollsBackEverything arms the outbox fault seam of a
// triage command: the failing append rolls the status change and the audit
// event back with it (TR-004) — no half-state.
func TestTriageOutboxFaultRollsBackEverything(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)

	cause := errors.New("outbox append failed")
	h.outbox.failpoint = application.InfraError("outbox.append", cause)

	_, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err == nil {
		t.Fatal("TransitionSignal succeeded despite the injected outbox error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error = %v, want the injected cause reachable via errors.Is", err)
	}
	tx := h.runner.last()
	if tx == nil || !tx.rolledBack || tx.committed {
		t.Fatalf("transaction rolledBack=%v committed=%v, want a rollback", tx.rolledBack, tx.committed)
	}
	// The status change and the audit write were rolled back: the signal is
	// still new and no transition audit row exists.
	if row, _ := h.db.signalRowByID(sig.ID); row.sig.Status != domain.SignalStatusNew || row.sig.Version != sig.Version {
		t.Fatalf("signal after rollback = %+v, want the unchanged new signal", row.sig)
	}
	if len(h.db.auditEvents) != 1 || len(h.db.outboxEvents) != 1 {
		t.Fatalf("rows after rollback: audit=%d outbox=%d, want only the seed rows", len(h.db.auditEvents), len(h.db.outboxEvents))
	}
}

// ---------------------------------------------------------------------------
// DEV-076 — SLA clock fulfilment + reopen reset (ARCH-004 §4.3)

// TestAcknowledgeFulfilsAcknowledgementClock proves the AcknowledgeSignal
// command fulfils the acknowledgement clock (ARCH-004 §4.3) in the same
// transaction as the status change, and fabricates no clock: exactly the
// seeded acknowledgement clock exists afterwards and it is fulfilled at the
// injected instant.
func TestAcknowledgeFulfilsAcknowledgementClock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	seedClock(h, sig.ID, domain.SLATargetAcknowledgement, fixedNow.Add(15*time.Minute))

	if _, err := h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("AcknowledgeSignal: %v", err)
	}

	clock, ok := h.db.slaClockByKey(sig.ID, domain.SLATargetAcknowledgement)
	if !ok {
		t.Fatal("acknowledgement clock missing after the command")
	}
	if !clock.Fulfilled() || !clock.FulfilledAt.Equal(fixedNow) {
		t.Fatalf("acknowledgement clock = %+v, want fulfilled at %v", clock, fixedNow)
	}
	// The create path defines the four P1 clocks; the command fulfils only
	// the acknowledgement one and fabricates none.
	if got := len(h.db.slaClocks); got != 4 {
		t.Fatalf("sla clocks = %d, want the 4 P1 clocks the create defined", got)
	}
	for _, target := range []domain.SLATarget{
		domain.SLATargetNotification, domain.SLATargetAssessment, domain.SLATargetDecision,
	} {
		if c, _ := h.db.slaClockByKey(sig.ID, target); c.Fulfilled() {
			t.Fatalf("%s clock = %+v, want unfulfilled (only acknowledgement is met)", target, c)
		}
	}
}

// TestAcknowledgeWithoutClockIsNoOp proves a missing acknowledgement clock is
// a no-op: the command succeeds and creates no clock. A P4 signal defines no
// acknowledgement target (ch. 9.4), so its only clock is the assessment one.
func TestAcknowledgeWithoutClockIsNoOp(t *testing.T) {
	h := newHarness(t)
	sig := seedSignalWithFactors(t, h, p4Factors())
	if sig.Priority != domain.PriorityP4 {
		t.Fatalf("seeded priority = %s, want P4", sig.Priority)
	}

	if _, err := h.svc.AcknowledgeSignal(context.Background(), application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("AcknowledgeSignal: %v", err)
	}
	// Only the P4 assessment clock exists; the fulfil created and fulfilled
	// nothing.
	if got := len(h.db.slaClocks); got != 1 {
		t.Fatalf("sla clocks = %d, want only the P4 assessment clock", got)
	}
	if c, ok := h.db.slaClockByKey(sig.ID, domain.SLATargetAssessment); !ok || c.Fulfilled() {
		t.Fatalf("assessment clock = %+v (ok=%v), want present and unfulfilled", c, ok)
	}
}

// TestTransitionFulfilsAssessmentAndDecisionOnce proves → action_planned
// co-fulfils assessment + decision (ARCH-004 §4.3) and that a later closed
// transition does not move an already-fulfilled clock (idempotent fulfil).
func TestTransitionFulfilsAssessmentAndDecisionOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	seedClock(h, sig.ID, domain.SLATargetAssessment, fixedNow.Add(time.Hour))
	seedClock(h, sig.ID, domain.SLATargetDecision, fixedNow.Add(4*time.Hour))

	planned, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("-> action_planned: %v", err)
	}
	for _, target := range []domain.SLATarget{domain.SLATargetAssessment, domain.SLATargetDecision} {
		clock, ok := h.db.slaClockByKey(sig.ID, target)
		if !ok || !clock.Fulfilled() || !clock.FulfilledAt.Equal(fixedNow) {
			t.Fatalf("%s clock = %+v (ok=%v), want fulfilled at %v", target, clock, ok, fixedNow)
		}
	}

	// A later closed transition re-attempts the fulfil; the clock keeps its
	// original fulfilment instant (never re-opened).
	h.clock.Advance(time.Hour)
	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusAccepted, Reason: "risk accepted", ExpectedVersion: planned.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("-> accepted: %v", err)
	}
	for _, target := range []domain.SLATarget{domain.SLATargetAssessment, domain.SLATargetDecision} {
		clock, _ := h.db.slaClockByKey(sig.ID, target)
		if !clock.FulfilledAt.Equal(fixedNow) {
			t.Fatalf("%s fulfilled_at = %v, want the unchanged %v (idempotent fulfil)", target, clock.FulfilledAt, fixedNow)
		}
	}
}

// TestTransitionNotAffectedFulfilsAssessmentOnly proves → not_affected
// fulfils the assessment clock and leaves the decision clock open
// (ARCH-004 §4.3).
func TestTransitionNotAffectedFulfilsAssessmentOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	seedClock(h, sig.ID, domain.SLATargetAssessment, fixedNow.Add(time.Hour))
	seedClock(h, sig.ID, domain.SLATargetDecision, fixedNow.Add(4*time.Hour))

	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusNotAffected, Reason: "no affected asset", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("-> not_affected: %v", err)
	}
	if clock, _ := h.db.slaClockByKey(sig.ID, domain.SLATargetAssessment); !clock.Fulfilled() {
		t.Fatalf("assessment clock = %+v, want fulfilled", clock)
	}
	if clock, _ := h.db.slaClockByKey(sig.ID, domain.SLATargetDecision); clock.Fulfilled() {
		t.Fatalf("decision clock = %+v, want still open on not_affected", clock)
	}
}

// TestTransitionP3HasNoDecisionClock proves the profile guard: P3 defines no
// decision clock, so → action_planned fulfils the assessment clock and
// leaves any decision clock untouched (ARCH-004 §4.2/§4.3).
func TestTransitionP3HasNoDecisionClock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h) // computed P1
	seedClock(h, sig.ID, domain.SLATargetAssessment, fixedNow.Add(72*time.Hour))
	seedClock(h, sig.ID, domain.SLATargetDecision, fixedNow.Add(72*time.Hour))

	// Effective priority P3 (no decision clock in the default profile).
	downgraded, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP3, Reason: "plausible only", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("OverridePriority: %v", err)
	}
	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: downgraded.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("-> action_planned: %v", err)
	}

	if clock, _ := h.db.slaClockByKey(sig.ID, domain.SLATargetAssessment); !clock.Fulfilled() {
		t.Fatalf("assessment clock = %+v, want fulfilled (P3 defines it)", clock)
	}
	if clock, _ := h.db.slaClockByKey(sig.ID, domain.SLATargetDecision); clock.Fulfilled() {
		t.Fatalf("decision clock = %+v, want untouched (P3 defines no decision clock)", clock)
	}
}

// TestReopenResetsClocks proves a reopen (a closed state → in_review) resets
// every clock defined at the current priority to a fresh window
// (ARCH-004 §4.3): started_at = now, deadline_at = now + duration,
// fulfilled_at cleared, pause counters zeroed.
func TestReopenResetsClocks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h) // P1: all four clocks defined

	// Seed every clock fulfilled/closed-window and stale.
	for _, target := range []domain.SLATarget{
		domain.SLATargetNotification, domain.SLATargetAcknowledgement,
		domain.SLATargetAssessment, domain.SLATargetDecision,
	} {
		seedClock(h, sig.ID, target, fixedNow.Add(24*time.Hour))
	}
	closed, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusNotAffected, Reason: "no affected asset", ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	})
	if err != nil {
		t.Fatalf("-> not_affected: %v", err)
	}
	if clock, _ := h.db.slaClockByKey(sig.ID, domain.SLATargetAssessment); !clock.Fulfilled() {
		t.Fatal("assessment clock not fulfilled before the reopen")
	}

	reopenAt := fixedNow.Add(30 * time.Minute)
	h.clock.Advance(30 * time.Minute)
	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusInReview, Reason: "new evidence", ExpectedVersion: closed.Version, Actor: systemActor("analyst"),
	}); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	want := map[domain.SLATarget]time.Duration{
		domain.SLATargetNotification:    5 * time.Minute,
		domain.SLATargetAcknowledgement: 15 * time.Minute,
		domain.SLATargetAssessment:      60 * time.Minute,
		domain.SLATargetDecision:        4 * time.Hour,
	}
	for target, d := range want {
		clock, ok := h.db.slaClockByKey(sig.ID, target)
		if !ok {
			t.Fatalf("%s clock missing after the reopen", target)
		}
		if clock.Fulfilled() {
			t.Fatalf("%s clock = %+v, want fulfilled_at cleared on reopen", target, clock)
		}
		if !clock.StartedAt.Equal(reopenAt) {
			t.Fatalf("%s started_at = %v, want the reopen instant %v", target, clock.StartedAt, reopenAt)
		}
		if wantDeadline := reopenAt.Add(d); !clock.DeadlineAt.Equal(wantDeadline) {
			t.Fatalf("%s deadline_at = %v, want %v (now + duration)", target, clock.DeadlineAt, wantDeadline)
		}
		if clock.PausedSeconds != 0 || clock.Paused() {
			t.Fatalf("%s pause counters = %d/%v, want zeroed", target, clock.PausedSeconds, clock.PausedAt)
		}
	}
}

// TestTriageOutboxFaultRollsBackClockMutation proves the fault seam covers
// the clock treatment: a failing outbox append rolls the fulfilled clock back
// with the status change — no half-state (TR-004).
func TestTriageOutboxFaultRollsBackClockMutation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	sig := seedSignal(t, h)
	seedClock(h, sig.ID, domain.SLATargetAssessment, fixedNow.Add(time.Hour))

	h.outbox.failpoint = application.InfraError("outbox.append", errors.New("outbox append failed"))
	if _, err := h.svc.TransitionSignal(ctx, application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version, Actor: systemActor("analyst"),
	}); err == nil {
		t.Fatal("TransitionSignal succeeded despite the injected outbox error")
	}

	clock, _ := h.db.slaClockByKey(sig.ID, domain.SLATargetAssessment)
	if clock.Fulfilled() {
		t.Fatalf("assessment clock = %+v, want the fulfil rolled back with the transition", clock)
	}
	if row, _ := h.db.signalRowByID(sig.ID); row.sig.Status != domain.SignalStatusNew {
		t.Fatalf("signal status = %s, want the unchanged new after the rollback", row.sig.Status)
	}
}
