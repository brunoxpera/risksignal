package application_test

// I6 exit-criteria consolidation (ARCH-007 §12/§13, WP-6.12 / DEV-134).
//
// This file gathers the I6 acceptance/fault-injection proofs of the
// application layer into one `I6ExitCriteria`-named suite, mirroring the
// I4/I5a/I5b `-run '...ExitCriteria'` convention of the Makefile targets. It
// deliberately does not re-implement the landed proofs (WP-6.04/6.05 /
// DEV-114/116): each subtest delegates to the existing proof function, so the
// suite is the consolidated gate over the same assertions, and the standalone
// proofs stay the per-work-package evidence.
//
// Covered here:
//   - AT-014 (export): create → frozen filter → materialise → download (audit,
//     expiry via the FakeClock, idempotent regenerate, expiry sweep);
//   - AT-014 fault injection (a): a failing export.generate job append rolls
//     the exports row back;
//   - AT-021 + NFR-015 (retention): the counts-only dry-run, the four-eyes
//     approval, the referentially-safe deletion order, the legal-hold block and
//     the in-place pseudonymisation;
//   - AT-021 fault injection (b): a failing retention batch stops only that
//     batch and leaves the run resumable (the new proof below).

import (
	"context"
	"errors"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// TestI6ExitCriteriaExportMaterialisation is the AT-014 acceptance case: the
// export lifecycle — a frozen filter, an atomic row+job, an idempotent
// regenerate, a time-limited download (expiry via the FakeClock) and the
// expiry sweep — as one named gate.
func TestI6ExitCriteriaExportMaterialisation(t *testing.T) {
	t.Run("create freezes the filter and enqueues one job", func(t *testing.T) {
		TestCreateExportFreezesFilterAndEnqueuesJob(t)
	})
	t.Run("create injects the owner scope", func(t *testing.T) {
		TestCreateExportInjectsOwnerScopeForAssignedGrant(t)
	})
	t.Run("denied create writes nothing", func(t *testing.T) {
		TestCreateExportDeniedWritesNothing(t)
	})
	t.Run("invalid filter and format are rejected", func(t *testing.T) {
		TestCreateExportRejectsInvalidFilterAndFormat(t)
	})
	t.Run("generate materialises the artifact", func(t *testing.T) {
		TestGenerateExportMaterialisesArtifact(t)
	})
	t.Run("generate is idempotent", func(t *testing.T) {
		TestGenerateExportIsIdempotent(t)
	})
	t.Run("generate records a failure", func(t *testing.T) {
		TestGenerateExportRecordsFailure(t)
	})
	t.Run("download streams and audits", func(t *testing.T) {
		TestDownloadExportStreamsAndAudits(t)
	})
	t.Run("download expires via the fake clock", func(t *testing.T) {
		TestDownloadExportExpiryViaFakeClock(t)
	})
	t.Run("download rejects not-completed and denied", func(t *testing.T) {
		TestDownloadExportRejectsNotCompletedAndDenied(t)
	})
	t.Run("sweep deletes the artifact and marks expired", func(t *testing.T) {
		TestSweepExportsDeletesArtifactAndMarksExpired(t)
	})
	t.Run("export source is filtered and ordered", func(t *testing.T) {
		TestSignalExportSourceFilteredOrdered(t)
	})
	t.Run("export source consumes the frozen filter", func(t *testing.T) {
		TestSignalExportSourceConsumesFrozenFilter(t)
	})
	t.Run("get export honours object scope", func(t *testing.T) {
		TestGetExportObjectScope(t)
	})
}

// TestI6ExitCriteriaExportFaultInjectionJobAppend is the ARCH-007 §12 fault
// injection (a): a failing export.generate job append rolls the exports row
// back — no orphaned export without its job.
func TestI6ExitCriteriaExportFaultInjectionJobAppend(t *testing.T) {
	t.Run("failing job append rolls back the exports row", func(t *testing.T) {
		TestCreateExportRollsBackOnFailedJobAppend(t)
	})
}

// TestI6ExitCriteriaRetentionLifecycle is the AT-021 + NFR-015 acceptance
// case: the governed retention run — counts-only dry-run (no state change),
// mandatory four-eyes approval, the referentially-safe deletion order, the
// legal-hold override, the surviving retention report and the in-place
// pseudonymisation — as one named gate. The accelerated clock boundaries
// (T+5y−1d vs T+5y+1d) and determinism come from the injected FakeClock the
// delegated proofs drive.
func TestI6ExitCriteriaRetentionLifecycle(t *testing.T) {
	t.Run("dry-run stores a counts-only report", func(t *testing.T) {
		TestRunRetentionDryRunStoresCountsOnlyReport(t)
	})
	t.Run("dry-run is deny-by-default", func(t *testing.T) {
		TestRunRetentionDryRunDenyByDefault(t)
	})
	t.Run("approval is four-eyes", func(t *testing.T) {
		TestApproveRetentionRunFourEyes(t)
	})
	t.Run("execute requires an approved run", func(t *testing.T) {
		TestExecuteRetentionRequiresApprovedRun(t)
	})
	t.Run("execute deletes in the safe order", func(t *testing.T) {
		TestExecuteRetentionDeletesInSafeOrder(t)
	})
	t.Run("legal hold blocks deletion", func(t *testing.T) {
		TestExecuteRetentionHoldBlocks(t)
	})
	t.Run("pseudonymisation redacts in place", func(t *testing.T) {
		TestPseudonymizeIdentityRedactsTargetsInPlace(t)
	})
	t.Run("pseudonymisation dry-run changes nothing", func(t *testing.T) {
		TestPseudonymizeIdentityDryRunChangesNothing(t)
	})
	t.Run("legal-hold lifecycle and gate", func(t *testing.T) {
		TestLegalHoldLifecycleAndGate(t)
	})
	t.Run("the report lists the retention runs", func(t *testing.T) {
		TestListRetentionRunsReportsTheReport(t)
	})
	t.Run("report reads are denied without retention.manage", func(t *testing.T) {
		TestListRetentionRunsDenied(t)
	})
	t.Run("run read is happy and not-found", func(t *testing.T) {
		TestGetRetentionRunHappyAndNotFound(t)
	})
}

// TestI6ExitCriteriaRetentionBatchFailureResumable is the ARCH-007 §12 fault
// injection (b): a failing retention batch stops only that batch (the others
// commit), the run is closed failed with the failed-batch count and the last
// error, and a re-run — once the fault is cleared — re-scans the candidates
// and completes the remaining signal (the run is resumable).
//
// It reuses the batch fault seam of the retention fakes
// (fakeRetentionRepo.failDeleteSignal) with a bounded batch size of one, so
// exactly one of the three single-signal batches fails while the run continues
// with the next.
func TestI6ExitCriteriaRetentionBatchFailureResumable(t *testing.T) {
	h := newHarness(t, func(d *application.ServiceDeps) { d.RetentionBatchSize = 1 })
	ctx := context.Background()
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	h.users.add("po", "PO", domain.RoleProductOwner)

	for _, id := range []string{"s1", "s2", "s3"} {
		seedRetainedSignal(h, id, "m-"+id)
		seedRetentionCandidate(h, id, fixedNow.AddDate(-6, 0, 0))
	}

	dry, err := h.svc.RunRetentionDryRun(ctx, application.RunRetentionDryRunInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if _, err := h.svc.ApproveRetentionRun(ctx, application.ApproveRetentionRunInput{RunID: dry.RunID, Reason: "due", Actor: userActor("po")}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Inject: the single-signal batch of s2 fails; the s1 and s3 batches still
	// commit, so the failure is confined to one batch.
	h.retention.failDeleteSignal = map[string]error{"s2": errors.New("injected deletion failure")}

	res, err := h.svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{RunID: dry.RunID, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Status != application.RetentionStatusFailed || res.FailedBatches != 1 || res.Deleted != 2 {
		t.Fatalf("execute result = %+v, want failed with 1 failed batch and 2 deleted", res)
	}

	// The two healthy batches committed; the failing batch rolled the signal,
	// its dependents and its pseudonymisation back whole.
	if storedSignalExists(h, "s1") || storedSignalExists(h, "s3") {
		t.Fatal("a healthy batch did not delete its signal")
	}
	if !storedSignalExists(h, "s2") {
		t.Fatal("the failing batch deleted its signal (the batch did not roll back)")
	}
	if len(h.db.comments) != 1 {
		t.Fatalf("retained comments = %d, want exactly the failing signal's row", len(h.db.comments))
	}

	// The report survives failed, with the failed-batch count and the error.
	run, _ := h.db.runByID(dry.RunID)
	if run.Status != application.RetentionStatusFailed || run.Deleted != 2 || run.Failed != 1 || run.LastError == "" {
		t.Fatalf("retention report = %+v, want failed with deleted=2, failed=1 and a last error", run)
	}
	// One retention.executed audit event per committed batch (the failed batch
	// wrote none).
	executed := 0
	for _, ev := range h.db.auditEvents {
		if ev.Action == application.EventTypeRetentionExecuted {
			executed++
		}
	}
	if executed != 2 {
		t.Fatalf("retention.executed audit rows = %d, want 2 (one per committed batch)", executed)
	}

	// Resumable: with the fault cleared and the run re-approved, the re-scan
	// finds only the surviving signal and completes the run.
	h.retention.failDeleteSignal = nil
	run.Status = application.RetentionStatusApproved
	h.db.applyRetentionRun(run)

	res2, err := h.svc.ExecuteRetention(ctx, application.ExecuteRetentionInput{RunID: dry.RunID, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("re-execute: %v", err)
	}
	if res2.Status != application.RetentionStatusCompleted || res2.Deleted != 1 || res2.FailedBatches != 0 {
		t.Fatalf("re-execute result = %+v, want completed with the remaining signal deleted", res2)
	}
	if storedSignalExists(h, "s2") {
		t.Fatal("the resumed run did not delete the remaining signal")
	}
}
