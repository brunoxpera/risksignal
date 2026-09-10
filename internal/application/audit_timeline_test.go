package application_test

// Unit tests of the DEV-110 ListAuditEvents read use case (ARCH-006 §3.1):
// the permission gate (audit.read per the §12.2 matrix — an `own`/`assigned`
// grant restricts the read to the principal's owned signal, `all` is
// unconditional) and the ordered timeline. All run against the in-memory
// fakes; no database and no transaction.

import (
	"context"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// seedSignalView inserts one joined signal read row (the owner the
// ListAuditEvents object-scope check resolves on).
func seedSignalView(h *harness, id, owner string) {
	h.db.signalViews = append(h.db.signalViews, application.Signal{ID: id, Owner: owner})
}

// seedAuditRow appends one committed audit event.
func seedAuditRow(h *harness, id, aggType, aggID, action string, at time.Time) {
	h.db.auditEvents = append(h.db.auditEvents, application.AuditEvent{
		ID: id, AggregateType: aggType, AggregateID: aggID,
		ActorType: application.ActorTypeUser, ActorID: "u-actor", Action: action, OccurredAt: at,
	})
}

func TestListAuditEventsOrdersTheTimeline(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	seedSignalView(h, "s1", "u-other")
	// Seeded out of order to prove the read orders by occurred_at.
	seedAuditRow(h, "e2", application.AuditAggregateRiskSignal, "s1", "signal.commented", fixedNow.Add(2*time.Minute))
	seedAuditRow(h, "e1", application.AuditAggregateRiskSignal, "s1", "signal.created", fixedNow)
	seedAuditRow(h, "e3", application.AuditAggregateRiskSignal, "s1", "signal.acknowledged", fixedNow.Add(time.Minute))
	// A foreign aggregate must not appear.
	seedAuditRow(h, "other", application.AuditAggregateRiskSignal, "s9", "signal.created", fixedNow)

	res, err := h.svc.ListAuditEvents(context.Background(), application.ListAuditEventsInput{SignalID: "s1", Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(res.Events))
	}
	want := []string{"e1", "e3", "e2"}
	for i, id := range want {
		if res.Events[i].ID != id {
			t.Fatalf("event[%d] = %q, want %q (timeline not ordered)", i, res.Events[i].ID, id)
		}
	}
}

func TestListAuditEventsOwnScopeDeniesNonOwner(t *testing.T) {
	h := newHarness(t)
	// The Analyst holds audit.read at the `own` scope.
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	seedSignalView(h, "s1", "u-other")
	seedAuditRow(h, "e1", application.AuditAggregateRiskSignal, "s1", "signal.created", fixedNow)

	_, err := h.svc.ListAuditEvents(context.Background(), application.ListAuditEventsInput{SignalID: "s1", Actor: userActor("analyst")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("non-owner own-scoped read = %v (%s), want forbidden", err, kind)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("denied read opened %d transactions, want 0", len(h.runner.txs))
	}
}

func TestListAuditEventsOwnScopeAllowsOwner(t *testing.T) {
	h := newHarness(t)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	seedSignalView(h, "s1", "analyst") // the principal owns the signal
	seedAuditRow(h, "e1", application.AuditAggregateRiskSignal, "s1", "signal.created", fixedNow)

	res, err := h.svc.ListAuditEvents(context.Background(), application.ListAuditEventsInput{SignalID: "s1", Actor: userActor("analyst")})
	if err != nil {
		t.Fatalf("owner own-scoped read: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(res.Events))
	}
}

func TestListAuditEventsAssignedScopeDeniesNonOwner(t *testing.T) {
	h := newHarness(t)
	// The Systemverantwortliche holds audit.read at the `assigned` scope.
	h.users.add("sys", "Sys", domain.RoleSystemResponsible)
	seedSignalView(h, "s1", "u-other")
	seedAuditRow(h, "e1", application.AuditAggregateRiskSignal, "s1", "signal.created", fixedNow)

	_, err := h.svc.ListAuditEvents(context.Background(), application.ListAuditEventsInput{SignalID: "s1", Actor: userActor("sys")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("non-owner assigned-scoped read = %v (%s), want forbidden", err, kind)
	}
}

func TestListAuditEventsDeniesRolelessUser(t *testing.T) {
	h := newHarness(t)
	h.users.add("nobody", "Nobody")
	seedSignalView(h, "s1", "u-actor")

	_, err := h.svc.ListAuditEvents(context.Background(), application.ListAuditEventsInput{SignalID: "s1", Actor: userActor("nobody")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("role-less read = %v (%s), want forbidden", err, kind)
	}
}

func TestListAuditEventsUnknownSignalIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)

	_, err := h.svc.ListAuditEvents(context.Background(), application.ListAuditEventsInput{SignalID: "missing", Actor: userActor("admin")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("missing signal = %v (%s), want not-found", err, kind)
	}
}
