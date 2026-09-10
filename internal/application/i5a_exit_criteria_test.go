package application_test

// I5a exit-criteria proofs at the application layer (ARCH-005 §8):
//
//   (a) the (role × use case) matrix — every gated use case driven as every
//       role: an allowed call proceeds and, for an audited command, stamps
//       the acting principal into its audit row (actor_type = "user",
//       actor_id = users.id); a forbidden call is a 403 that opens no
//       transaction and writes no audit row; a role-less or unknown-role
//       principal is denied on everything (deny-by-default);
//   (c) object scope — a Systemverantwortliche acts only on its assigned
//       signal (transition/assign of an unassigned one is denied with no
//       audit; an assigned one succeeds with actor_id = users.id);
//   (f) thread-the-actor fault injection — a fault between the permission
//       check and the write rolls the state, the audit and the outbox back
//       together, and the committed audit row carries users.id / "user".
//
// The unauthenticated 401 half of (a) is proven at the HTTP boundary
// (cmd/risksignal-server TestUnauthenticatedRequestReturns401); here the
// "authenticated but role-less ⇒ 403 on everything" half is driven.

import (
	"context"
	"errors"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// i5aRoles registers the acting principal: one of the five roles, a role-less
// user, or a user holding only an unknown role (both of the latter are
// deny-by-default on everything).
func i5aRoles(t *testing.T, h *harness, id string) {
	t.Helper()
	switch id {
	case "role-less":
		h.users.add(id, "No Roles")
	case "unknown-role":
		h.users.add(id, "Unknown", domain.Role("security_lead"))
	default:
		h.users.add(id, "User", domain.Role(id))
	}
}

// i5aRoleIDs lists the acting principals in canonical order.
var i5aRoleIDs = []string{
	string(domain.RoleSecurityAnalyst),
	string(domain.RoleSystemResponsible),
	string(domain.RoleAdministrator),
	string(domain.RoleAuditor),
	string(domain.RoleProductOwner),
	"role-less",
	"unknown-role",
}

// i5aCommand is one gated use case driven cell-by-cell. seed runs before the
// baselines are taken (so setup writes do not count as the command's); invoke
// is the call under test.
type i5aCommand struct {
	name string
	// audited is true when a successful run writes exactly one audit row
	// whose actor is the acting principal.
	audited bool
	// succeeds reports whether an ALLOWED run is expected to return nil.
	// (inventory.manage has no in-memory happy path with an empty file, so
	// its allowed run may surface a validation error — the gate is proven by
	// the absence of a forbidden error.)
	succeeds bool
	// allowed maps a role to whether §12.2 grants its permission on the
	// seeded object.
	allowed map[domain.Role]bool
	seed    func(t *testing.T, h *harness, actorID string)
	invoke  func(h *harness, actorID string) error
}

func TestI5aExitCriteriaRoleUseCaseMatrix(t *testing.T) {
	allowAll := map[domain.Role]bool{
		domain.RoleSecurityAnalyst: true, domain.RoleSystemResponsible: true,
		domain.RoleAdministrator: true, domain.RoleAuditor: true, domain.RoleProductOwner: true,
	}
	seedViewsOwned := func(n int) func(*testing.T, *harness, string) {
		return func(_ *testing.T, h *harness, id string) {
			seedViews(h, n)
			for i := range h.db.signalViews {
				h.db.signalViews[i].Owner = id
			}
		}
	}
	ackCmd, overrideCmd := func() (i5aCommand, i5aCommand) {
		var ackSig, ovrSig domain.RiskSignal
		ack := i5aCommand{
			name: "acknowledge", audited: true, succeeds: true,
			allowed: map[domain.Role]bool{domain.RoleSecurityAnalyst: true, domain.RoleSystemResponsible: true},
			seed:    func(t *testing.T, h *harness, id string) { ackSig = seedOwnedSignal(t, h, id) },
			invoke: func(h *harness, id string) error {
				_, err := h.svc.AcknowledgeSignal(context.Background(), application.AcknowledgeSignalInput{
					SignalID: ackSig.ID, ExpectedVersion: ackSig.Version, Actor: userActor(id),
				})
				return err
			},
		}
		override := i5aCommand{
			name: "override", audited: true, succeeds: true,
			allowed: map[domain.Role]bool{domain.RoleSecurityAnalyst: true},
			seed:    func(t *testing.T, h *harness, id string) { ovrSig = seedOwnedSignal(t, h, id) },
			invoke: func(h *harness, id string) error {
				_, err := h.svc.OverridePriority(context.Background(), application.OverridePriorityInput{
					SignalID: ovrSig.ID, Priority: domain.PriorityP3, Reason: "decommissioned",
					ExpectedVersion: ovrSig.Version, Actor: userActor(id),
				})
				return err
			},
		}
		return ack, override
	}()
	cmds := []i5aCommand{
		{
			name: "list_signals", succeeds: true, allowed: allowAll,
			seed: seedViewsOwned(2),
			invoke: func(h *harness, id string) error {
				_, err := h.svc.ListSignals(context.Background(), application.ListSignalsInput{Limit: 100, Actor: userActor(id)})
				return err
			},
		},
		{
			name: "get_signal", succeeds: true, allowed: allowAll,
			seed: seedViewsOwned(1),
			invoke: func(h *harness, id string) error {
				_, err := h.svc.GetSignal(context.Background(), application.GetSignalInput{SignalID: h.db.signalViews[0].ID, Actor: userActor(id)})
				return err
			},
		},
		ackCmd,
		overrideCmd,
		{
			name: "commit_inventory", succeeds: false,
			allowed: map[domain.Role]bool{domain.RoleAdministrator: true},
			invoke: func(h *harness, id string) error {
				_, err := h.svc.CommitInventory(context.Background(), application.CommitInventoryInput{Actor: userActor(id)})
				return err
			},
		},
		{
			name: "publish_rules", audited: true, succeeds: true,
			allowed: map[domain.Role]bool{domain.RoleAdministrator: true},
			invoke: func(h *harness, id string) error {
				_, err := h.svc.PublishPriorityRules(context.Background(), application.PublishPriorityRulesInput{Reason: "quarterly", Actor: userActor(id)})
				return err
			},
		},
		{
			name: "quarantine_ack", audited: true, succeeds: true,
			allowed: map[domain.Role]bool{domain.RoleAdministrator: true},
			seed:    func(t *testing.T, h *harness, _ string) { seedQuarantined(h, t) },
			invoke: func(h *harness, id string) error {
				_, err := h.svc.QuarantineAck(context.Background(), application.QuarantineAckInput{ID: "quar-1", Note: "reviewed", Actor: userActor(id)})
				return err
			},
		},
		{
			name: "reveal", audited: true, succeeds: true,
			allowed: map[domain.Role]bool{domain.RoleAuditor: true, domain.RoleProductOwner: true},
			seed: func(_ *testing.T, h *harness, _ string) {
				h.users.add("victim", "Victim User")
				seedAuditEvent(h, "audit-matrix", application.ActorTypeUser, "victim", "Victim User")
			},
			invoke: func(h *harness, id string) error {
				_, err := h.svc.RevealAuditIdentity(context.Background(), application.RevealAuditIdentityInput{
					EventID: "audit-matrix", Reason: "subject access request", Actor: userActor(id),
				})
				return err
			},
		},
	}

	for _, cmd := range cmds {
		for _, id := range i5aRoleIDs {
			t.Run(cmd.name+"/"+id, func(t *testing.T) {
				h := newHarness(t)
				i5aRoles(t, h, id)
				if cmd.seed != nil {
					cmd.seed(t, h, id)
				}

				auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
				err := cmd.invoke(h, id)

				if !cmd.allowed[domain.Role(id)] {
					// Forbidden ⇒ 403 and no write (no transaction, no audit).
					assertForbidden(t, err)
					assertNoWrite(t, h, auditBefore, txBefore)
					return
				}
				if err != nil {
					if kind, _ := application.ErrorKindOf(err); kind == application.KindForbidden {
						t.Fatalf("allowed command was denied: %v", err)
					}
					if cmd.succeeds {
						t.Fatalf("allowed command returned %v, want success", err)
					}
					return // allowed, but no in-memory happy path (inventory.manage)
				}
				if !cmd.audited {
					return
				}
				// An audited allowed command writes exactly one audit row and
				// stamps the acting principal (actor_type = "user",
				// actor_id = users.id).
				if got := len(h.db.auditEvents) - auditBefore; got != 1 {
					t.Fatalf("allowed command wrote %d audit rows, want exactly 1", got)
				}
				last := h.db.auditEvents[len(h.db.auditEvents)-1]
				if last.ActorType != application.ActorTypeUser || last.ActorID != id {
					t.Fatalf("audit actor = %s/%s, want user/%s (users.id)", last.ActorType, last.ActorID, id)
				}
			})
		}
	}
}

// i5aOwnedSignal seeds one signal under a unique match id and, when owner is
// non-empty, assigns it to owner through the real AssignOwner command (a
// system-actor setup path), so a test can hold several independent signals.
func i5aOwnedSignal(t *testing.T, h *harness, matchID, owner string) domain.RiskSignal {
	t.Helper()
	res, err := h.svc.CreateSignal(context.Background(), application.CreateSignalInput{
		MatchID: matchID, CveID: testCveID, Factors: p1Factors(), Actor: systemActor("setup"),
	})
	if err != nil {
		t.Fatalf("seed CreateSignal: %v", err)
	}
	sig := res.Signal
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

// TestI5aExitCriteriaObjectScope is the ARCH-005 §8(c) object-scope proof: a
// Systemverantwortliche acts only on the signals it owns, in both the read and
// the write path; the assigned owner is stamped as users.id.
func TestI5aExitCriteriaObjectScope(t *testing.T) {
	h := newHarness(t)
	h.users.add("resp", "Responsible", domain.RoleSystemResponsible)
	ctx := context.Background()

	// Two signals: one assigned to resp, one to somebody else (unique match
	// ids so each CreateSignal stands alone).
	own := i5aOwnedSignal(t, h, "22222222-2222-2222-2222-222222222201", "resp")
	other := i5aOwnedSignal(t, h, "22222222-2222-2222-2222-222222222202", "other-user")

	// Read scope: only the assigned row is visible.
	seedViews(h, 2)
	h.db.signalViews[0].Owner = "resp"
	h.db.signalViews[1].Owner = "other-user"
	page, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: 100, Actor: userActor("resp")})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range page.Signals {
		if s.Owner != "resp" {
			t.Fatalf("system_responsible saw a signal owned by %q, want only its own", s.Owner)
		}
	}

	// Write scope: the unassigned signal is denied (403, no audit); the
	// assigned one succeeds and stamps actor_id = users.id.
	auditBefore, txBefore := len(h.db.auditEvents), len(h.runner.txs)
	_, err = h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: other.ID, ExpectedVersion: other.Version, Actor: userActor("resp"),
	})
	assertForbidden(t, err)
	assertNoWrite(t, h, auditBefore, txBefore)

	auditBefore = len(h.db.auditEvents)
	if _, err := h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
		SignalID: own.ID, ExpectedVersion: own.Version, Actor: userActor("resp"),
	}); err != nil {
		t.Fatalf("acknowledge own signal denied: %v", err)
	}
	last := h.db.auditEvents[len(h.db.auditEvents)-1]
	if last.ActorType != application.ActorTypeUser || last.ActorID != "resp" {
		t.Fatalf("assigned acknowledge actor = %s/%s, want user/resp", last.ActorType, last.ActorID)
	}
	if got := len(h.db.auditEvents) - auditBefore; got != 1 {
		t.Fatalf("assigned acknowledge wrote %d audit rows, want 1", got)
	}

	// The same scope rule governs AssignOwner.
	third := i5aOwnedSignal(t, h, "22222222-2222-2222-2222-222222222203", "")
	auditBefore, txBefore = len(h.db.auditEvents), len(h.runner.txs)
	_, err = h.svc.AssignOwner(ctx, application.AssignOwnerInput{
		SignalID: third.ID, Owner: "resp", ExpectedVersion: third.Version, Actor: userActor("resp"),
	})
	assertForbidden(t, err)
	assertNoWrite(t, h, auditBefore, txBefore)
}

// TestI5aExitCriteriaThreadTheActorFaultInjection is the ARCH-005 §8(f) proof:
// a mutating command stamps the authenticated principal into its audit row,
// and a fault injected between the permission check and the write (the
// failing outbox append, the ARCH-001 §5 seam) rolls the state, the audit and
// the outbox back together — no unauthorised half-state.
func TestI5aExitCriteriaThreadTheActorFaultInjection(t *testing.T) {
	ctx := context.Background()

	t.Run("audit row carries users.id and actor_type user", func(t *testing.T) {
		h := newHarness(t)
		h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
		sig := seedOwnedSignal(t, h, "analyst")

		audited, err := h.svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
			SignalID: sig.ID, ExpectedVersion: sig.Version, Actor: userActor("analyst"),
		})
		if err != nil {
			t.Fatalf("AcknowledgeSignal: %v", err)
		}
		if audited.Status != domain.SignalStatusInReview {
			t.Fatalf("status = %s, want in_review", audited.Status)
		}
		ev := h.db.auditEvents[len(h.db.auditEvents)-1]
		if ev.ActorType != application.ActorTypeUser || ev.ActorID != "analyst" {
			t.Fatalf("audit actor = %s/%s, want user/analyst (users.id)", ev.ActorType, ev.ActorID)
		}
	})

	t.Run("fault between permission check and write rolls everything back", func(t *testing.T) {
		h := newHarness(t)
		h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
		sig := seedOwnedSignal(t, h, "analyst")

		before, ok := h.db.signalRowByID(sig.ID)
		if !ok {
			t.Fatalf("seeded signal missing")
		}
		auditsBefore := len(h.db.auditEvents)
		outboxBefore := len(h.db.outboxEvents)

		// Arm the ARCH-001 §5 seam: the outbox append fails after the guarded
		// write and the audit of the same transaction succeeded, so only a
		// complete rollback can hold.
		cause := errors.New("injected outbox append failure")
		h.outbox.failpoint = cause

		_, err := h.svc.OverridePriority(ctx, application.OverridePriorityInput{
			SignalID: sig.ID, Priority: domain.PriorityP3, Reason: "decommissioned",
			ExpectedVersion: sig.Version, Actor: userActor("analyst"),
		})
		if err == nil {
			t.Fatal("command succeeded, want the injected outbox error")
		}
		if !errors.Is(err, cause) {
			t.Fatalf("error = %v, want the injected error unwrapped", err)
		}

		// Complete rollback: the signal is unchanged, no audit and no outbox
		// row survived, and the transaction rolled back.
		after, _ := h.db.signalRowByID(sig.ID)
		if after.sig.Priority != before.sig.Priority || after.sig.Version != before.sig.Version || after.sig.Status != before.sig.Status {
			t.Fatalf("signal changed on a rolled-back command: %+v -> %+v", before.sig, after.sig)
		}
		if len(h.db.auditEvents) != auditsBefore {
			t.Fatalf("audit rows = %d, want %d (rolled back)", len(h.db.auditEvents), auditsBefore)
		}
		if len(h.db.outboxEvents) != outboxBefore {
			t.Fatalf("outbox rows = %d, want %d (rolled back)", len(h.db.outboxEvents), outboxBefore)
		}
		tx := h.runner.last()
		if tx == nil || !tx.rolledBack || tx.committed {
			t.Fatalf("transaction rolledBack=%v committed=%v, want a rolled-back one", tx.rolledBack, tx.committed)
		}
	})
}
