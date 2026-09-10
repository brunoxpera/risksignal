package application_test

// Unit tests of the governed audit.reveal_identity act (ARCH-005 §7,
// WP-5a.07 / DEV-094, ADR-014): the RevealAuditIdentity use case.
//
// Each test drives the real use case through the in-memory fakes and asserts
// the ADR-014 rules: the permission gate (Auditor/PO only, never Admin;
// denied writes nothing), the mandatory non-blank reason, the system/service
// label for a non-user actor, the resolution of a deactivated target, exactly
// one self-audit audit.identity_revealed per reveal, and the rollback of the
// whole reveal when the self-audit fails.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// seedAuditEvent seeds one committed audit row (the target of a reveal) into
// the fake audit store.
func seedAuditEvent(h *harness, id, actorType, actorID, displayName string) {
	h.db.auditEvents = append(h.db.auditEvents, application.AuditEvent{
		ID:               id,
		AggregateType:    application.AuditAggregateRiskSignal,
		AggregateID:      "00000000-0000-4000-8000-0000000000aa",
		ActorType:        actorType,
		ActorID:          actorID,
		ActorDisplayName: displayName,
		Action:           "signal.created",
		OccurredAt:       fixedNow,
		CorrelationID:    "corr-seed",
	})
}

// countReveals counts the audit.identity_revealed rows of the fake store.
func countReveals(events []application.AuditEvent) int {
	n := 0
	for _, ev := range events {
		if ev.Action == application.EventTypeAuditIdentityRevealed {
			n++
		}
	}
	return n
}

func revealInput(eventID, reason, actor string) application.RevealAuditIdentityInput {
	return application.RevealAuditIdentityInput{EventID: eventID, Reason: reason, Actor: userActor(actor)}
}

// TestRevealAuditIdentityAuditorAndProductOwner asserts Auditor and Product
// Owner may reveal; the resolved identity is returned and exactly one
// audit.identity_revealed self-audit is written per reveal.
func TestRevealAuditIdentityAuditorAndProductOwner(t *testing.T) {
	for _, role := range []domain.Role{domain.RoleAuditor, domain.RoleProductOwner} {
		t.Run(string(role), func(t *testing.T) {
			h := newHarness(t)
			h.users.add("revealer", "Revealer", role)
			h.users.add("victim", "Victim User")
			seedAuditEvent(h, "audit-1", application.ActorTypeUser, "victim", "Victim User")

			before := countReveals(h.db.auditEvents)
			res, err := h.svc.RevealAuditIdentity(context.Background(), revealInput("audit-1", "subject access request", "revealer"))
			if err != nil {
				t.Fatalf("reveal denied for %s: %v", role, err)
			}
			if !res.IsUser || res.UserID != "victim" || res.SubjectID != "victim" || res.Label != "Victim User" {
				t.Fatalf("result = %+v, want the resolved victim identity", res)
			}
			if res.EventID != "audit-1" || res.EventActorType != application.ActorTypeUser {
				t.Fatalf("result = %+v, want the revealed event metadata", res)
			}
			if got := countReveals(h.db.auditEvents) - before; got != 1 {
				t.Fatalf("reveal wrote %d audit.identity_revealed rows, want exactly 1", got)
			}
			// The self-audit carries the revealing principal and the target.
			last := h.db.auditEvents[len(h.db.auditEvents)-1]
			if last.ActorID != "revealer" || last.ActorType != application.ActorTypeUser {
				t.Fatalf("self-audit actor = %s/%s, want user/revealer", last.ActorType, last.ActorID)
			}
			if last.AggregateType != application.AuditAggregateAuditEvent || last.AggregateID != "audit-1" {
				t.Fatalf("self-audit aggregate = %s/%s, want audit_event/audit-1", last.AggregateType, last.AggregateID)
			}
		})
	}
}

// TestRevealAuditIdentityAdminDenied asserts the Administrator is denied and
// the denial writes nothing (no transaction, no audit row).
func TestRevealAuditIdentityAdminDenied(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("victim", "Victim User")
	seedAuditEvent(h, "audit-1", application.ActorTypeUser, "victim", "Victim User")

	auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
	_, err := h.svc.RevealAuditIdentity(context.Background(), revealInput("audit-1", "curious", "admin"))
	assertForbidden(t, err)
	assertNoWrite(t, h, auditBefore, txBefore)
}

// TestRevealAuditIdentityBlankReason asserts a blank reason is a validation
// error and writes no audit row (no reveal).
func TestRevealAuditIdentityBlankReason(t *testing.T) {
	h := newHarness(t)
	h.users.add("auditor", "Auditor", domain.RoleAuditor)
	h.users.add("victim", "Victim User")
	seedAuditEvent(h, "audit-1", application.ActorTypeUser, "victim", "Victim User")

	for _, reason := range []string{"", "   ", "\t\n"} {
		auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
		_, err := h.svc.RevealAuditIdentity(context.Background(), revealInput("audit-1", reason, "auditor"))
		if err == nil {
			t.Fatalf("blank reason %q accepted, want a validation error", reason)
		}
		if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
			t.Fatalf("error kind = %s, want validation (%v)", kind, err)
		}
		assertNoWrite(t, h, auditBefore, txBefore)
	}
}

// TestRevealAuditIdentityDeactivatedTargetResolves asserts a deactivated
// target user still resolves (the deactivated record is the key, ADR-014 §3).
func TestRevealAuditIdentityDeactivatedTargetResolves(t *testing.T) {
	h := newHarness(t)
	h.users.add("auditor", "Auditor", domain.RoleAuditor)
	h.users.add("victim", "Victim User")
	h.users.deactivate("victim", fixedNow.Add(time.Hour))
	seedAuditEvent(h, "audit-1", application.ActorTypeUser, "victim", "Victim User")

	res, err := h.svc.RevealAuditIdentity(context.Background(), revealInput("audit-1", "GDPR request", "auditor"))
	if err != nil {
		t.Fatalf("deactivated target did not resolve: %v", err)
	}
	if !res.IsUser || res.UserID != "victim" || res.Label != "Victim User" {
		t.Fatalf("result = %+v, want the deactivated victim resolved", res)
	}
	if countReveals(h.db.auditEvents) != 1 {
		t.Fatalf("want exactly one self-audit")
	}
}

// TestRevealAuditIdentitySystemActorReturnsLabel asserts a system/service
// target actor returns its own label and resolves no identity (nothing to
// reveal).
func TestRevealAuditIdentitySystemActorReturnsLabel(t *testing.T) {
	h := newHarness(t)
	h.users.add("auditor", "Auditor", domain.RoleAuditor)
	seedAuditEvent(h, "audit-sys", application.ActorTypeSystem, "sla.evaluate", "")

	auditBefore := len(h.db.auditEvents)
	res, err := h.svc.RevealAuditIdentity(context.Background(), revealInput("audit-sys", "check", "auditor"))
	if err != nil {
		t.Fatalf("reveal of a system actor failed: %v", err)
	}
	if res.IsUser || res.UserID != "" || res.SubjectID != "" {
		t.Fatalf("result = %+v, want no resolved identity for a system actor", res)
	}
	if res.Label != "sla.evaluate" || res.EventActorType != application.ActorTypeSystem {
		t.Fatalf("result = %+v, want the system label sla.evaluate", res)
	}
	if len(h.db.auditEvents) != auditBefore {
		t.Fatalf("system-actor reveal wrote %d audit rows, want none", len(h.db.auditEvents)-auditBefore)
	}
}

// TestRevealAuditIdentitySelfAuditFailureRollsBack asserts a failing
// self-audit rolls the whole reveal back and returns nothing (ADR-014 "in
// full or not at all").
func TestRevealAuditIdentitySelfAuditFailureRollsBack(t *testing.T) {
	h := newHarness(t)
	h.users.add("auditor", "Auditor", domain.RoleAuditor)
	h.users.add("victim", "Victim User")
	seedAuditEvent(h, "audit-1", application.ActorTypeUser, "victim", "Victim User")

	auditBefore := len(h.db.auditEvents)
	h.audit.failpoint = errors.New("self-audit write failed")

	res, err := h.svc.RevealAuditIdentity(context.Background(), revealInput("audit-1", "reason", "auditor"))
	if err == nil {
		t.Fatal("reveal succeeded although the self-audit failed, want the error")
	}
	if res != (application.RevealAuditIdentityResult{}) {
		t.Fatalf("result = %+v, want the zero result on rollback (nothing returned)", res)
	}
	if len(h.db.auditEvents) != auditBefore {
		t.Fatalf("rolled-back reveal left %d audit rows, want none", len(h.db.auditEvents)-auditBefore)
	}
	if len(h.runner.txs) != 1 || !h.runner.txs[0].rolledBack {
		t.Fatalf("want exactly one rolled-back transaction, got %d", len(h.runner.txs))
	}
}

// TestRevealAuditIdentityUnknownEventNotFound asserts an unknown event id is
// a not-found error and writes nothing.
func TestRevealAuditIdentityUnknownEventNotFound(t *testing.T) {
	h := newHarness(t)
	h.users.add("auditor", "Auditor", domain.RoleAuditor)

	_, err := h.svc.RevealAuditIdentity(context.Background(), revealInput("nope", "reason", "auditor"))
	if err == nil {
		t.Fatal("reveal of an unknown event succeeded, want a not-found error")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("error kind = %s, want not-found (%v)", kind, err)
	}
}

// TestResolveActorMapsSubject asserts the identity → actor resolution used by
// the authenticated adapters: a known subject resolves to the user actor with
// the internal id; an unknown subject denies (fail closed).
func TestResolveActorMapsSubject(t *testing.T) {
	h := newHarness(t)
	h.users.addWithSubject("uid-1", "local::auditor", "Auditor", domain.RoleAuditor)

	actor, err := h.svc.ResolveActor(context.Background(), domain.Identity{SubjectID: "local::auditor", DisplayName: "Auditor"})
	if err != nil {
		t.Fatalf("ResolveActor: %v", err)
	}
	if actor.Type != application.ActorTypeUser || actor.ID != "uid-1" || actor.DisplayName != "Auditor" {
		t.Fatalf("actor = %+v, want user/uid-1/Auditor", actor)
	}

	if _, err := h.svc.ResolveActor(context.Background(), domain.Identity{SubjectID: "local::ghost"}); err == nil {
		t.Fatal("unknown subject resolved, want a forbidden error")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("error kind = %s, want forbidden (%v)", kind, err)
	}
}
