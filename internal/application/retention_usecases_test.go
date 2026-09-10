package application_test

// Unit tests for the I6 retention and pseudonymisation use cases (ARCH-007
// §2/§3, WP-6.05 / DEV-116): the counts-only dry-run, the four-eyes approval,
// the referentially-safe deletion order, the legal-hold override, the in-place
// pseudonymisation redaction target set and its dry-run, all gated
// deny-by-default.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// seedRetentionCandidate seeds one closed signal due at the retention cutoff
// (the candidate scan derives the active-hold flag from the seeded holds).
func seedRetentionCandidate(h *harness, signalID string, closedAt time.Time) {
	h.db.retentionCandidates = append(h.db.retentionCandidates, application.RetentionCandidate{
		SignalID: signalID,
		ClosedAt: closedAt,
	})
}

// seedRetainedSignal seeds one closed signal with a dependent row in every
// table of the §2.3 deletion order, plus a shared evidence/vulnerability/
// raw-record chain that the retention must never touch.
func seedRetainedSignal(h *harness, signalID, matchID string) {
	h.db.signalRows = append(h.db.signalRows, storedSignal{
		sig: domain.RiskSignal{
			ID: signalID, MatchID: matchID, Status: domain.SignalStatusResolved,
			Owner: "u1", Version: 3, OverrideReason: "manager approved",
			OverrideActorID: "u1",
		},
		createdAt: fixedNow,
	})
	h.db.matchRows = append(h.db.matchRows, storedMatch{id: matchID, createdAt: fixedNow})
	h.db.comments = append(h.db.comments, domain.Comment{ID: "cm-" + signalID, SignalID: signalID, ActorID: "u1", Body: "contained a personal note"})
	h.db.slaClocks = append(h.db.slaClocks, domain.SlaClock{ID: "sc-" + signalID, SignalID: signalID, Target: domain.SLATargetAssessment})
	h.db.notifications = append(h.db.notifications, application.Notification{ID: "no-" + signalID, SignalID: signalID, Channel: "in_app"})
	h.db.priorityFactors = append(h.db.priorityFactors, retentionPriorityFactor{signalID: signalID})
	h.db.auditEvents = append(h.db.auditEvents, application.AuditEvent{
		ID:               "ae-" + signalID,
		AggregateType:    application.AuditAggregateRiskSignal,
		AggregateID:      signalID,
		ActorType:        "user",
		ActorID:          "u1",
		ActorDisplayName: "Alice",
		Action:           "signal.transitioned",
		OccurredAt:       fixedNow,
		After:            json.RawMessage(`{"reason":"closing the case","status":"resolved"}`),
	})
	h.db.vulns = append(h.db.vulns, storedVuln{id: "v-" + signalID, cveID: "CVE-2026-" + signalID})
	h.db.rawRecords = append(h.db.rawRecords, storedRawRecord{id: "rr-" + signalID})
	h.db.evidenceRows = append(h.db.evidenceRows, storedEvidence{id: "ev-" + signalID, rawID: "rr-" + signalID, vulnID: "v-" + signalID})
}

func storedSignalExists(h *harness, id string) bool {
	for _, s := range h.db.signalRows {
		if s.sig.ID == id {
			return true
		}
	}
	return false
}

// TestRunRetentionDryRunStoresCountsOnlyReport: the dry-run splits the due
// signals into the actionable candidates and the held ones, stores a
// counts-only report row and writes no audit row nor any state change.
func TestRunRetentionDryRunStoresCountsOnlyReport(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)

	due := fixedNow.AddDate(-6, 0, 0)
	seedRetentionCandidate(h, "s1", due)
	seedRetentionCandidate(h, "s2", due.Add(time.Hour))
	seedRetentionCandidate(h, "s3", fixedNow.AddDate(-1, 0, 0)) // not due yet
	h.db.signalRows = append(h.db.signalRows,
		storedSignal{sig: domain.RiskSignal{ID: "s1", MatchID: "m1"}},
		storedSignal{sig: domain.RiskSignal{ID: "s2", MatchID: "m2"}},
	)
	h.db.legalHolds = append(h.db.legalHolds, application.LegalHold{
		ID: "hold-1", AggregateType: application.AuditAggregateRiskSignal, AggregateID: "s2",
		Reason: "litigation 2026-05", ActorID: "admin", CreatedAt: fixedNow,
	})

	res, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("RunRetentionDryRun: %v", err)
	}
	if res.Status != application.RetentionStatusDryRun {
		t.Fatalf("status = %q, want dry_run", res.Status)
	}
	want := application.RetentionCounts{Candidates: 1, Held: 1, ToDelete: 1}
	if res.Counts != want {
		t.Fatalf("counts = %+v, want %+v", res.Counts, want)
	}
	if len(res.Held) != 1 || res.Held[0].SignalID != "s2" || res.Held[0].HoldReason != "litigation 2026-05" {
		t.Fatalf("held = %+v, want s2 with the documented reason", res.Held)
	}
	if !res.Cutoff.Equal(fixedNow.AddDate(-5, 0, 0)) {
		t.Fatalf("cutoff = %s, want %s", res.Cutoff, fixedNow.AddDate(-5, 0, 0))
	}
	if len(h.db.retentionRuns) != 1 {
		t.Fatalf("stored runs = %d, want 1", len(h.db.retentionRuns))
	}
	run := h.db.retentionRuns[0]
	if run.Status != application.RetentionStatusDryRun || run.Stage != application.RetentionStageDelete {
		t.Fatalf("stored run = %+v, want dry_run/delete", run)
	}
	if run.DryRun == nil || *run.DryRun != want {
		t.Fatalf("stored report = %+v, want %+v", run.DryRun, want)
	}
	if len(h.db.auditEvents) != 0 {
		t.Fatalf("dry-run wrote %d audit rows, want 0", len(h.db.auditEvents))
	}
	if !storedSignalExists(h, "s1") || !storedSignalExists(h, "s2") {
		t.Fatal("dry-run changed domain state")
	}
}

// TestRunRetentionDryRunDenyByDefault: a principal without retention.manage is
// denied before any transaction or read — nothing is stored.
func TestRunRetentionDryRunDenyByDefault(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	seedRetentionCandidate(h, "s1", fixedNow.AddDate(-6, 0, 0))

	if _, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("analyst")}); err == nil {
		t.Fatal("dry-run by an unpermitted principal succeeded")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("error kind = %v, want forbidden", kind)
	}
	if len(h.db.retentionRuns) != 0 {
		t.Fatal("a denied dry-run stored a run")
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("a denied dry-run opened %d transactions, want 0", len(h.runner.txs))
	}
}

// TestApproveRetentionRunFourEyes: only settings.approve (Product Owner) can
// approve, with a mandatory reason; a rejection records the rejected state.
func TestApproveRetentionRunFourEyes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	h.users.add("po", "PO", domain.RoleProductOwner)
	seedRetentionCandidate(h, "s1", fixedNow.AddDate(-6, 0, 0))

	dry, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}

	// A principal without settings.approve is denied; the run stays dry_run.
	if _, err := h.svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{RunID: dry.RunID, Reason: "due", Actor: userActor("analyst")}); err == nil {
		t.Fatal("approval by an unpermitted principal succeeded")
	}
	if run, _ := h.db.runByID(dry.RunID); run.Status != application.RetentionStatusDryRun {
		t.Fatalf("denied approval changed the run to %q", run.Status)
	}
	if len(h.db.auditEvents) != 0 {
		t.Fatal("a denied approval wrote an audit row")
	}

	// A blank reason is rejected before any write.
	if _, err := h.svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{RunID: dry.RunID, Reason: "  ", Actor: userActor("po")}); err == nil {
		t.Fatal("approval with a blank reason succeeded")
	}

	// The Product Owner approves.
	res, err := h.svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{RunID: dry.RunID, Reason: "5y elapsed", Actor: userActor("po")})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if res.Status != application.RetentionStatusApproved || res.ApprovedBy != "po" || res.ApprovedAt.IsZero() {
		t.Fatalf("approve result = %+v, want approved by po at an instant", res)
	}
	run, _ := h.db.runByID(dry.RunID)
	if run.Status != application.RetentionStatusApproved || run.ApprovalReason != "5y elapsed" || run.ApprovedBy != "po" {
		t.Fatalf("stored run = %+v, want the recorded approval", run)
	}
	if len(h.db.auditEvents) != 1 || h.db.auditEvents[0].Action != application.EventTypeRetentionApproved {
		t.Fatalf("audit = %+v, want one retention.approved", h.db.auditEvents)
	}

	// A second run can be rejected instead.
	dry2, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("second dry-run: %v", err)
	}
	if _, err := h.svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{RunID: dry2.RunID, Reason: "not now", Reject: true, Actor: userActor("po")}); err != nil {
		t.Fatalf("reject: %v", err)
	}
	run2, _ := h.db.runByID(dry2.RunID)
	if run2.Status != application.RetentionStatusRejected {
		t.Fatalf("rejected run status = %q, want rejected", run2.Status)
	}
	if h.db.auditEvents[len(h.db.auditEvents)-1].Action != application.EventTypeRetentionRejected {
		t.Fatal("rejection did not write a retention.rejected audit row")
	}
}

// TestExecuteRetentionRequiresApprovedRun: deletion only runs on an approved
// run; an unapproved run conflicts and nothing is deleted.
func TestExecuteRetentionRequiresApprovedRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	seedRetainedSignal(h, "s1", "m1")
	seedRetentionCandidate(h, "s1", fixedNow.AddDate(-6, 0, 0))

	dry, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if _, err := h.svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{RunID: dry.RunID, Actor: userActor("admin")}); err == nil {
		t.Fatal("executing a dry_run run succeeded")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("error kind = %v, want conflict", kind)
	}
	if !storedSignalExists(h, "s1") {
		t.Fatal("an unapproved run deleted a signal")
	}

	// A principal without retention.manage cannot execute.
	if _, err := h.svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{RunID: dry.RunID, Actor: userActor("analyst")}); err == nil {
		t.Fatal("execution by an unpermitted principal succeeded")
	}
}

// TestExecuteRetentionDeletesInSafeOrder: an approved delete run pseudonymises
// first and deletes the signal's dependents in the §2.3 order, leaves the
// shared data alone, audits the batch and leaves the report behind.
func TestExecuteRetentionDeletesInSafeOrder(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("po", "PO", domain.RoleProductOwner)
	seedRetainedSignal(h, "s1", "m1")
	seedRetentionCandidate(h, "s1", fixedNow.AddDate(-6, 0, 0))

	dry, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if _, err := h.svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{RunID: dry.RunID, Reason: "due", Actor: userActor("po")}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	res, err := h.svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{RunID: dry.RunID, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Status != application.RetentionStatusCompleted || res.Deleted != 1 || res.Pseudonymised != 1 {
		t.Fatalf("execute result = %+v, want completed with 1 deleted / 1 pseudonymised", res)
	}

	// The referentially-safe order is the batch transaction's recorded order.
	var batch *fakeTx
	for _, tx := range h.runner.txs {
		for _, op := range tx.log {
			if op == "retention.pseudonymise_signal" {
				batch = tx
			}
		}
	}
	if batch == nil {
		t.Fatal("no batch transaction recorded a pseudonymisation")
	}
	var batchOps []string
	for _, op := range batch.log {
		if strings.HasPrefix(op, "retention.") {
			batchOps = append(batchOps, op)
		}
	}
	wantOrder := []string{
		"retention.pseudonymise_signal",
		"retention.delete_sla_clocks",
		"retention.delete_comments",
		"retention.delete_matches",
		"retention.delete_notifications",
		"retention.delete_priority_factors",
		"retention.delete_audit_events",
		"retention.delete_risk_signals",
	}
	if len(batchOps) != len(wantOrder) {
		t.Fatalf("batch ops = %v, want %v", batchOps, wantOrder)
	}
	for i := range wantOrder {
		if batchOps[i] != wantOrder[i] {
			t.Fatalf("batch op %d = %q, want %q (full: %v)", i, batchOps[i], wantOrder[i], batchOps)
		}
	}

	// The signal and every non-shared dependent are gone.
	if storedSignalExists(h, "s1") {
		t.Fatal("the signal survived the delete run")
	}
	if len(h.db.comments) != 0 || len(h.db.slaClocks) != 0 || len(h.db.matchRows) != 0 ||
		len(h.db.notifications) != 0 || len(h.db.priorityFactors) != 0 {
		t.Fatalf("non-shared dependents survived: comments=%d clocks=%d matches=%d notifications=%d factors=%d",
			len(h.db.comments), len(h.db.slaClocks), len(h.db.matchRows), len(h.db.notifications), len(h.db.priorityFactors))
	}
	// Shared data is never deleted by signal retention.
	if len(h.db.vulns) != 1 || len(h.db.rawRecords) != 1 || len(h.db.evidenceRows) != 1 {
		t.Fatalf("shared data was touched: vulns=%d raws=%d evidences=%d", len(h.db.vulns), len(h.db.rawRecords), len(h.db.evidenceRows))
	}

	// The report survives with the final counts.
	run, _ := h.db.runByID(dry.RunID)
	if run.Status != application.RetentionStatusCompleted || run.Deleted != 1 || run.Pseudonymised != 1 {
		t.Fatalf("report = %+v, want completed with the final counts", run)
	}
	// The batch audit carries counts and the processed time range only.
	var executed *application.AuditEvent
	for i := range h.db.auditEvents {
		if h.db.auditEvents[i].Action == application.EventTypeRetentionExecuted {
			executed = &h.db.auditEvents[i]
		}
	}
	if executed == nil {
		t.Fatal("no retention.executed audit row")
	}
	if executed.AggregateType != application.AuditAggregateRetention || executed.AggregateID != dry.RunID {
		t.Fatalf("executed audit = %+v, want aggregate retention/%s", executed, dry.RunID)
	}
	var snap map[string]any
	if err := json.Unmarshal(executed.After, &snap); err != nil {
		t.Fatalf("executed snapshot: %v", err)
	}
	if snap["deleted"].(float64) != 1 || snap["from"] == nil || snap["to"] == nil {
		t.Fatalf("executed snapshot = %v, want counts + time range", snap)
	}
}

// TestExecuteRetentionHoldBlocks: an active legal hold set after the approval
// blocks the deletion of its signal.
func TestExecuteRetentionHoldBlocks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("po", "PO", domain.RoleProductOwner)
	seedRetainedSignal(h, "s1", "m1")
	seedRetentionCandidate(h, "s1", fixedNow.AddDate(-6, 0, 0))

	dry, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if _, err := h.svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{RunID: dry.RunID, Reason: "due", Actor: userActor("po")}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// A hold is set between the approval and the execution.
	if _, err := h.svc.CreateLegalHold(ctx, application.CreateLegalHoldInput{AggregateID: "s1", Reason: "regulator request", Actor: userActor("admin")}); err != nil {
		t.Fatalf("create hold: %v", err)
	}

	res, err := h.svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{RunID: dry.RunID, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Deleted != 0 || res.Pseudonymised != 0 {
		t.Fatalf("execute result = %+v, want nothing processed under a hold", res)
	}
	if !storedSignalExists(h, "s1") || len(h.db.comments) != 1 {
		t.Fatal("a held signal was deleted or redacted")
	}

	// A fresh dry-run reports the held candidate.
	dry2, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("dry-run 2: %v", err)
	}
	if dry2.Counts.Candidates != 0 || dry2.Counts.Held != 1 {
		t.Fatalf("held dry-run counts = %+v, want 0 candidates / 1 held", dry2.Counts)
	}
}

// TestPseudonymizeIdentityRedactsTargetsInPlace: the real run clears the display
// names and redacts the free text (comment bodies, override reasons, snapshot
// reasons) in place, keeps actor_id and audits the act.
func TestPseudonymizeIdentityRedactsTargetsInPlace(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	seedRetainedSignal(h, "s1", "m1")
	// A second identity's audit row must stay untouched.
	h.db.auditEvents = append(h.db.auditEvents, application.AuditEvent{
		ID: "ae-u2", AggregateType: application.AuditAggregateRiskSignal, AggregateID: "s1",
		ActorType: "user", ActorID: "u2", ActorDisplayName: "Bob", Action: "signal.commented", OccurredAt: fixedNow,
	})

	res, err := h.svc.PseudonymizeIdentity(ctx, application.PseudonymizeIdentityInput{
		UserID: "u1", Reason: "DSR-42", Actor: userActor("admin"),
	})
	if err != nil {
		t.Fatalf("pseudonymise: %v", err)
	}
	if res.DryRun || res.Redaction.Total() == 0 {
		t.Fatalf("result = %+v, want a real run with a non-empty redaction", res)
	}

	var u1 *application.AuditEvent
	var u2 *application.AuditEvent
	for i := range h.db.auditEvents {
		switch h.db.auditEvents[i].ID {
		case "ae-s1":
			u1 = &h.db.auditEvents[i]
		case "ae-u2":
			u2 = &h.db.auditEvents[i]
		}
	}
	if u1 == nil || u2 == nil {
		t.Fatalf("seeded audit rows missing: u1=%v u2=%v", u1, u2)
	}
	// Identity cleared, structured fields and actor_id retained.
	if u1.ActorDisplayName != "" || u1.ActorID != "u1" || u1.Action != "signal.transitioned" || !u1.OccurredAt.Equal(fixedNow) {
		t.Fatalf("u1 audit row = %+v, want cleared name with retained identity/structure", u1)
	}
	// The other identity is untouched.
	if u2.ActorDisplayName != "Bob" {
		t.Fatalf("u2 display name = %q, want Bob (untouched)", u2.ActorDisplayName)
	}
	// Free text redacted in place, structured snapshot keys kept.
	var snap map[string]any
	if err := json.Unmarshal(u1.After, &snap); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap["reason"] != application.RetentionRedactionMarker {
		t.Fatalf("snapshot reason = %v, want the redaction marker", snap["reason"])
	}
	if snap["status"] != "resolved" {
		t.Fatalf("structured snapshot key lost: %v", snap)
	}
	if h.db.comments[0].Body != application.RetentionRedactionMarker {
		t.Fatalf("comment body = %q, want redacted", h.db.comments[0].Body)
	}
	if h.db.signalRows[0].sig.OverrideReason != "" {
		t.Fatalf("override reason = %q, want cleared", h.db.signalRows[0].sig.OverrideReason)
	}
	// The pseudonymisation is audited.
	var audited bool
	for _, ev := range h.db.auditEvents {
		if ev.Action == application.EventTypeRetentionPseudonymised {
			audited = true
			if ev.AggregateID != "u1" || ev.AggregateType != application.AuditAggregateUser {
				t.Fatalf("pseudonymise audit = %+v, want aggregate user/u1", ev)
			}
		}
	}
	if !audited {
		t.Fatal("no retention.pseudonymised audit row")
	}
}

// TestPseudonymizeIdentityDryRunChangesNothing: the dry-run reports the counts
// but changes no row, writes no audit row and opens no transaction.
func TestPseudonymizeIdentityDryRunChangesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	seedRetainedSignal(h, "s1", "m1")

	res, err := h.svc.PseudonymizeIdentity(ctx, application.PseudonymizeIdentityInput{
		UserID: "u1", DryRun: true, Actor: userActor("admin"),
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !res.DryRun || res.Redaction.Total() == 0 {
		t.Fatalf("dry-run result = %+v, want counts without a change", res)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("a dry-run opened %d transactions, want 0", len(h.runner.txs))
	}
	if len(h.db.auditEvents) != 1 || h.db.auditEvents[0].ActorDisplayName == "" {
		t.Fatalf("a dry-run changed the audit rows: %+v", h.db.auditEvents)
	}
	if h.db.comments[0].Body == application.RetentionRedactionMarker {
		t.Fatal("a dry-run redacted a comment body")
	}
	if h.db.signalRows[0].sig.OverrideReason == "" {
		t.Fatal("a dry-run cleared an override reason")
	}
}

// TestLegalHoldLifecycleAndGate: the create/list/release lifecycle is gated on
// retention.manage, requires a documented reason and is audited.
func TestLegalHoldLifecycleAndGate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)

	// Deny-by-default and the mandatory reason.
	if _, err := h.svc.CreateLegalHold(ctx, application.CreateLegalHoldInput{AggregateID: "s1", Reason: "x", Actor: userActor("analyst")}); err == nil {
		t.Fatal("hold created by an unpermitted principal")
	}
	if len(h.db.legalHolds) != 0 || len(h.db.auditEvents) != 0 {
		t.Fatal("a denied hold create wrote state")
	}
	if _, err := h.svc.CreateLegalHold(ctx, application.CreateLegalHoldInput{AggregateID: "s1", Reason: " ", Actor: userActor("admin")}); err == nil {
		t.Fatal("hold created without a reason")
	}

	hold, err := h.svc.CreateLegalHold(ctx, application.CreateLegalHoldInput{AggregateID: "s1", Reason: "investigation", Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("create hold: %v", err)
	}
	if !hold.Active() || hold.Reason != "investigation" || hold.ActorID != "admin" {
		t.Fatalf("stored hold = %+v", hold)
	}
	if h.db.auditEvents[0].Action != application.EventTypeRetentionHoldCreated {
		t.Fatalf("audit = %+v, want retention.hold_created", h.db.auditEvents)
	}

	active := true
	holds, err := h.svc.ListLegalHolds(ctx, application.ListLegalHoldsInput{Active: &active, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("list holds: %v", err)
	}
	if len(holds) != 1 || holds[0].ID != hold.ID {
		t.Fatalf("active holds = %+v, want the created hold", holds)
	}

	released, err := h.svc.ReleaseLegalHold(ctx, application.ReleaseLegalHoldInput{HoldID: hold.ID, Reason: "cleared", Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("release hold: %v", err)
	}
	if released.Active() {
		t.Fatal("released hold still reports active")
	}
	if h.db.auditEvents[len(h.db.auditEvents)-1].Action != application.EventTypeRetentionHoldReleased {
		t.Fatal("release did not write a retention.hold_released audit row")
	}
	holds, err = h.svc.ListLegalHolds(ctx, application.ListLegalHoldsInput{Active: &active, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("list holds after release: %v", err)
	}
	if len(holds) != 0 {
		t.Fatalf("active holds after release = %+v, want none", holds)
	}
}
