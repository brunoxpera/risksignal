package application_test

// Unit tests of the I5a use-case authorisation seam (ARCH-005 §5, WP-5a.06):
// the deny-by-default gate every user-invokable use case runs. Each test
// drives the real use case through the in-memory fakes with a user actor and
// asserts (a) the allowed/denied outcome per the §12.2 matrix, (b) that a
// denial opens no transaction and writes no audit row, and (c) the
// object-scope filter (read) and owner check (write).

import (
	"context"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// userActor is the authenticated-user audit actor of the authorizer tests
// (ARCH-005 §6: Type = "user", ID = users.id).
func userActor(id string) application.Actor {
	return application.Actor{Type: application.ActorTypeUser, ID: id}
}

// seedOwnedSignal creates one signal through the CreateSignal command and,
// when owner is non-empty, assigns it to owner through the real AssignOwner
// command under a system actor (the ungated setup path). The current signal
// (with its bumped version) is returned.
func seedOwnedSignal(t *testing.T, h *harness, owner string) domain.RiskSignal {
	t.Helper()
	sig := seedSignal(t, h)
	if owner == "" {
		return sig
	}
	owned, err := h.svc.AssignOwner(context.Background(), application.AssignOwnerInput{
		SignalID: sig.ID, Owner: owner, ExpectedVersion: sig.Version, Actor: systemActor("setup"),
	})
	if err != nil {
		t.Fatalf("seed AssignOwner: %v", err)
	}
	return owned
}

// assertForbidden asserts err is a forbidden-class application error (403).
func assertForbidden(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("command succeeded, want a forbidden error")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("error kind = %s, want forbidden (%v)", kind, err)
	}
}

// assertNoWrite asserts the denied call opened no transaction and appended no
// audit row (the deny-before-transaction rule of ARCH-005 §5).
func assertNoWrite(t *testing.T, h *harness, auditBefore, txBefore int) {
	t.Helper()
	if got := len(h.db.auditEvents); got != auditBefore {
		t.Fatalf("denied command wrote %d audit row(s) (audit %d -> %d), want none", got-auditBefore, auditBefore, got)
	}
	if got := len(h.runner.txs); got != txBefore {
		t.Fatalf("denied command opened %d transaction(s) (tx %d -> %d), want none", got-txBefore, txBefore, got)
	}
}

// TestTriageAuthorisationMatrix drives TransitionSignal as every role against
// owned and unowned signals: the Analyst (all) passes unconditionally, the
// Systemverantwortliche (assigned) passes only on its own signal, and every
// other role (and the role-less user) is denied with no write.
func TestTriageAuthorisationMatrix(t *testing.T) {
	cases := []struct {
		name      string
		roles     []domain.Role
		owner     string
		wantAllow bool
	}{
		{"analyst-any", []domain.Role{domain.RoleSecurityAnalyst}, "someone", true},
		{"analyst-unowned", []domain.Role{domain.RoleSecurityAnalyst}, "", true},
		{"system-responsible-own", []domain.Role{domain.RoleSystemResponsible}, "u1", true},
		{"system-responsible-other", []domain.Role{domain.RoleSystemResponsible}, "other", false},
		{"system-responsible-unowned", []domain.Role{domain.RoleSystemResponsible}, "", false},
		{"administrator-denied", []domain.Role{domain.RoleAdministrator}, "u1", false},
		{"auditor-denied", []domain.Role{domain.RoleAuditor}, "u1", false},
		{"product-owner-denied", []domain.Role{domain.RoleProductOwner}, "u1", false},
		{"role-less-denied", nil, "u1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.users.add("u1", "User One", tc.roles...)
			sig := seedOwnedSignal(t, h, tc.owner)

			auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
			_, err := h.svc.TransitionSignal(context.Background(), application.TransitionSignalInput{
				SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version, Actor: userActor("u1"),
			})
			if tc.wantAllow {
				if err != nil {
					t.Fatalf("want allowed, got %v", err)
				}
				if len(h.db.auditEvents) != auditBefore+1 {
					t.Fatalf("allowed command wrote %d audit rows, want 1", len(h.db.auditEvents)-auditBefore)
				}
				return
			}
			assertForbidden(t, err)
			assertNoWrite(t, h, auditBefore, txBefore)
		})
	}
}

// TestTriageDeniedStampsNothing asserts a denied triage leaves the signal
// untouched (no staged mutation committed, no outbox row).
func TestTriageDeniedStampsNothing(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	sig := seedOwnedSignal(t, h, "")
	before, ok := h.db.signalRowByID(sig.ID)
	if !ok {
		t.Fatalf("seeded signal %s missing", sig.ID)
	}
	outboxBefore := len(h.db.outboxEvents)

	_, err := h.svc.AcknowledgeSignal(context.Background(), application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: userActor("admin"),
	})
	assertForbidden(t, err)

	after, _ := h.db.signalRowByID(sig.ID)
	if after.sig.Status != before.sig.Status || after.sig.Version != before.sig.Version {
		t.Fatalf("denied command changed the signal: %s/%d -> %s/%d", before.sig.Status, before.sig.Version, after.sig.Status, after.sig.Version)
	}
	if len(h.db.outboxEvents) != outboxBefore {
		t.Fatalf("denied command enqueued an outbox row")
	}
}

// TestOverrideRevertC4Gate asserts the C-4 carry-over: signals.override is
// the Analyst's alone; Administrator (and every other role) is denied, and the
// denial precedes the domain checks (an invalid input is still a 403).
func TestOverrideRevertC4Gate(t *testing.T) {
	denied := []struct {
		name  string
		roles []domain.Role
	}{
		{"administrator", []domain.Role{domain.RoleAdministrator}},
		{"system-responsible", []domain.Role{domain.RoleSystemResponsible}},
		{"auditor", []domain.Role{domain.RoleAuditor}},
		{"product-owner", []domain.Role{domain.RoleProductOwner}},
		{"role-less", nil},
	}
	for _, tc := range denied {
		t.Run("override-"+tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.users.add("u1", "User One", tc.roles...)
			sig := seedOwnedSignal(t, h, "")
			auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
			_, err := h.svc.OverridePriority(context.Background(), application.OverridePriorityInput{
				SignalID: sig.ID, Priority: domain.PriorityP3, Reason: "decommissioned", ExpectedVersion: sig.Version, Actor: userActor("u1"),
			})
			assertForbidden(t, err)
			assertNoWrite(t, h, auditBefore, txBefore)
		})
		t.Run("revert-"+tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.users.add("u1", "User One", tc.roles...)
			sig := seedOwnedSignal(t, h, "")
			auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
			_, err := h.svc.RevertPriority(context.Background(), application.RevertPriorityInput{
				SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: userActor("u1"),
			})
			assertForbidden(t, err)
			assertNoWrite(t, h, auditBefore, txBefore)
		})
	}

	// The Analyst holds signals.override: override then revert both succeed.
	h := newHarness(t)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	sig := seedOwnedSignal(t, h, "")
	overridden, err := h.svc.OverridePriority(context.Background(), application.OverridePriorityInput{
		SignalID: sig.ID, Priority: domain.PriorityP3, Reason: "asset decommissioned", ExpectedVersion: sig.Version, Actor: userActor("analyst"),
	})
	if err != nil {
		t.Fatalf("analyst override denied: %v", err)
	}
	if overridden.OverrideActorID != "analyst" {
		t.Fatalf("override actor = %q, want analyst (users.id)", overridden.OverrideActorID)
	}
	if _, err := h.svc.RevertPriority(context.Background(), application.RevertPriorityInput{
		SignalID: sig.ID, ExpectedVersion: overridden.Version, Actor: userActor("analyst"),
	}); err != nil {
		t.Fatalf("analyst revert denied: %v", err)
	}
}

// TestOverrideGatePrecedesValidation asserts the C-4 gate is at the top of the
// command: an Admin is denied before the expected_version/domain checks, so an
// otherwise-invalid input still answers 403 (not a validation error).
func TestOverrideGatePrecedesValidation(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)

	_, err := h.svc.OverridePriority(context.Background(), application.OverridePriorityInput{
		SignalID: "", Priority: "nonsense", Reason: "", ExpectedVersion: 0, Actor: userActor("admin"),
	})
	assertForbidden(t, err)
	assertNoWrite(t, h, auditBefore, txBefore)
}

// TestDeactivatedUserDenies asserts a deactivated principal is denied on every
// gated command (it still resolves in the audit trail but holds no rights).
func TestDeactivatedUserDenies(t *testing.T) {
	h := newHarness(t)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	h.users.deactivate("analyst", fixedNow.Add(time.Hour))
	sig := seedOwnedSignal(t, h, "")
	auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)

	_, err := h.svc.TransitionSignal(context.Background(), application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version, Actor: userActor("analyst"),
	})
	assertForbidden(t, err)
	assertNoWrite(t, h, auditBefore, txBefore)
}

// TestUnknownUserDenies asserts an unknown users.id denies (fail closed).
func TestUnknownUserDenies(t *testing.T) {
	h := newHarness(t)
	sig := seedOwnedSignal(t, h, "")
	auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)

	_, err := h.svc.TransitionSignal(context.Background(), application.TransitionSignalInput{
		SignalID: sig.ID, To: domain.SignalStatusActionPlanned, ExpectedVersion: sig.Version, Actor: userActor("ghost"),
	})
	assertForbidden(t, err)
	assertNoWrite(t, h, auditBefore, txBefore)
}

// TestListSignalsObjectScope asserts the query-path object scope: a
// Systemverantwortliche (assigned) sees only its owned signals, the Analyst
// (all) sees every signal, and a role-less user is denied.
func TestListSignalsObjectScope(t *testing.T) {
	h := newHarness(t)
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	h.users.add("nobody", "Nobody")
	seedViews(h, 4)
	h.db.signalViews[0].Owner = "resp"
	h.db.signalViews[1].Owner = "other"
	h.db.signalViews[2].Owner = "resp"
	h.db.signalViews[3].Owner = ""

	resp, err := h.svc.ListSignals(context.Background(), application.ListSignalsInput{Limit: 100, Actor: userActor("resp")})
	if err != nil {
		t.Fatalf("system_responsible list: %v", err)
	}
	if len(resp.Signals) != 2 {
		t.Fatalf("system_responsible saw %d signals, want 2 (its owned rows)", len(resp.Signals))
	}
	for _, s := range resp.Signals {
		if s.Owner != "resp" {
			t.Fatalf("system_responsible saw a signal owned by %q, want only resp", s.Owner)
		}
	}

	analyst, err := h.svc.ListSignals(context.Background(), application.ListSignalsInput{Limit: 100, Actor: userActor("analyst")})
	if err != nil {
		t.Fatalf("analyst list: %v", err)
	}
	if len(analyst.Signals) != 4 {
		t.Fatalf("analyst saw %d signals, want all 4", len(analyst.Signals))
	}

	_, err = h.svc.ListSignals(context.Background(), application.ListSignalsInput{Limit: 100, Actor: userActor("nobody")})
	assertForbidden(t, err)
}

// TestGetSignalObjectScope asserts the command-path object scope on the single
// read: a Systemverantwortliche reads only its owned signal, the Analyst reads
// any, and a role-less user is denied before the view is returned.
func TestGetSignalObjectScope(t *testing.T) {
	h := newHarness(t)
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	h.users.add("nobody", "Nobody")
	h.db.signalViews = append(h.db.signalViews,
		application.Signal{ID: "s1", Priority: domain.PriorityP1, Status: domain.SignalStatusNew, Owner: "resp"},
		application.Signal{ID: "s2", Priority: domain.PriorityP2, Status: domain.SignalStatusNew, Owner: "other"},
	)

	if _, err := h.svc.GetSignal(context.Background(), application.GetSignalInput{SignalID: "s1", Actor: userActor("resp")}); err != nil {
		t.Fatalf("system_responsible denied its own signal: %v", err)
	}
	_, err := h.svc.GetSignal(context.Background(), application.GetSignalInput{SignalID: "s2", Actor: userActor("resp")})
	assertForbidden(t, err)

	if _, err := h.svc.GetSignal(context.Background(), application.GetSignalInput{SignalID: "s2", Actor: userActor("analyst")}); err != nil {
		t.Fatalf("analyst denied an unowned signal: %v", err)
	}
	_, err = h.svc.GetSignal(context.Background(), application.GetSignalInput{SignalID: "s1", Actor: userActor("nobody")})
	assertForbidden(t, err)
}

// TestWriteCommandGates covers the inventory/sources/rules commands: a role
// without the permission is denied before any work, and the permitted role
// proceeds.
func TestWriteCommandGates(t *testing.T) {
	t.Run("inventory-manage-denies-analyst", func(t *testing.T) {
		h := newHarness(t)
		h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
		auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
		_, err := h.svc.CommitInventory(context.Background(), application.CommitInventoryInput{Actor: userActor("analyst")})
		assertForbidden(t, err)
		assertNoWrite(t, h, auditBefore, txBefore)
	})
	t.Run("sources-manage-denies-auditor", func(t *testing.T) {
		h := newHarness(t)
		h.users.add("auditor", "Auditor", domain.RoleAuditor)
		auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
		_, err := h.svc.QuarantineAck(context.Background(), application.QuarantineAckInput{ID: "q1", Actor: userActor("auditor")})
		assertForbidden(t, err)
		assertNoWrite(t, h, auditBefore, txBefore)
	})
	t.Run("rules-manage-denies-analyst-allows-admin", func(t *testing.T) {
		h := newHarness(t)
		h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
		h.users.add("admin", "Admin", domain.RoleAdministrator)
		auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
		_, err := h.svc.PublishPriorityRules(context.Background(), application.PublishPriorityRulesInput{Reason: "quarterly", Actor: userActor("analyst")})
		assertForbidden(t, err)
		assertNoWrite(t, h, auditBefore, txBefore)

		if _, err := h.svc.PublishPriorityRules(context.Background(), application.PublishPriorityRulesInput{Reason: "quarterly", Actor: userActor("admin")}); err != nil {
			t.Fatalf("administrator denied rules.manage: %v", err)
		}
	})
}

// TestRoutePrincipalResolvesAndDenies asserts the route-level principal
// resolution the HTTP PermissionGate consults (ARCH-005 §5): a known active
// user resolves with its current roles, while a missing subject, an unknown
// subject and a deactivated user all deny (fail closed). It decides no
// permission and no object scope — the use case remains the gate of record.
func TestRoutePrincipalResolvesAndDenies(t *testing.T) {
	h := newHarness(t)
	h.users.addWithSubject("u1", "local::analyst", "Analyst", domain.RoleSecurityAnalyst)

	p, err := h.svc.RoutePrincipal(context.Background(), domain.Identity{SubjectID: "local::analyst"})
	if err != nil {
		t.Fatalf("RoutePrincipal: %v", err)
	}
	if p.InternalID != "u1" || len(p.Roles) != 1 || p.Roles[0] != domain.RoleSecurityAnalyst {
		t.Fatalf("principal = %+v, want u1 holding security_analyst", p)
	}

	_, err = h.svc.RoutePrincipal(context.Background(), domain.Identity{})
	assertForbidden(t, err)

	_, err = h.svc.RoutePrincipal(context.Background(), domain.Identity{SubjectID: "local::ghost"})
	assertForbidden(t, err)

	h.users.deactivate("u1", fixedNow.Add(time.Hour))
	_, err = h.svc.RoutePrincipal(context.Background(), domain.Identity{SubjectID: "local::analyst"})
	assertForbidden(t, err)
}

// TestSystemActorNotGated asserts the internal boundary: a gated use case
// invoked by a system actor (the trusted worker/CLI process) is not
// user-authorised and proceeds (ARCH-005 §5).
func TestSystemActorNotGated(t *testing.T) {
	h := newHarness(t)
	sig := seedOwnedSignal(t, h, "")
	if _, err := h.svc.AcknowledgeSignal(context.Background(), application.AcknowledgeSignalInput{
		SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: systemActor("sla.evaluate"),
	}); err != nil {
		t.Fatalf("system actor denied a gated command: %v", err)
	}
}
