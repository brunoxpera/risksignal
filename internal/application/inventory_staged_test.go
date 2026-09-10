package application_test

// Unit tests of the I5b staged inventory-import orchestration (WP-5b.03 /
// DEV-099, ARCH-006 §2.1): StageInventoryImport (validate + preview + persist
// a pending record), GetInventoryImport (by-id read) and CommitStagedInventory
// (reuse the I3 CommitInventory over the stored bytes, stamp the four counters
// atomically with the commit-mark, re-commit is a no-op), plus the
// deny-by-default gate. All run against the in-memory fakes; no database.

import (
	"context"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

func TestStageInventoryImportValidatesPreviewsAndPersistsPending(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))

	res, err := h.svc.StageInventoryImport(context.Background(), application.StageInventoryImportInput{
		File:  []byte(csv),
		Actor: userActor("admin"),
	})
	if err != nil {
		t.Fatalf("StageInventoryImport: %v", err)
	}
	if res.ID == "" {
		t.Fatal("staged import has no id")
	}
	if res.Status != application.InventoryImportPending {
		t.Fatalf("status = %q, want pending", res.Status)
	}
	if res.Rows != 1 || res.ErrorCount != 0 {
		t.Fatalf("rows=%d errors=%d, want 1/0", res.Rows, res.ErrorCount)
	}
	if res.AssetsCreated != 1 || res.ComponentsCreated != 1 {
		t.Fatalf("preview tallies assets=%d components=%d, want 1/1", res.AssetsCreated, res.ComponentsCreated)
	}
	if len(h.db.imports) != 1 || h.db.imports[0].Status != application.InventoryImportPending {
		t.Fatalf("persisted records = %d, want 1 pending", len(h.db.imports))
	}
	// Staging never writes to the inventory.
	if len(h.db.assets) != 0 {
		t.Fatalf("staging wrote %d assets to the inventory, want 0", len(h.db.assets))
	}

	// The by-id read returns the stored record with the re-derived report.
	got, err := h.svc.GetInventoryImport(context.Background(), application.GetInventoryImportInput{ID: res.ID, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("GetInventoryImport: %v", err)
	}
	if got.Status != application.InventoryImportPending || got.Rows != 1 {
		t.Fatalf("get = status %q rows %d, want pending/1", got.Status, got.Rows)
	}
}

func TestStageInventoryImportReportsPositionedProblems(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	// An out-of-vocabulary type is a positioned problem: the row never writes,
	// but the staged record still persists (only the commit's clean rows apply).
	bad := commitRow("cmdb", "a1", "bogus_type", "host", "production", "high", "internet", "", "Acme", "Portal", "1.0.0", "", "", "", "")
	csv := commitCSV(bad)

	res, err := h.svc.StageInventoryImport(context.Background(), application.StageInventoryImportInput{File: []byte(csv), Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("StageInventoryImport: %v", err)
	}
	if res.ErrorCount != 1 || len(res.Problems) != 1 {
		t.Fatalf("errors=%d problems=%d, want 1/1", res.ErrorCount, len(res.Problems))
	}
	if res.AssetsCreated != 0 {
		t.Fatalf("preview created %d assets from a fully-failing file, want 0", res.AssetsCreated)
	}
}

func TestCommitStagedInventoryPopulatesTheFourCounters(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))

	staged, err := h.svc.StageInventoryImport(context.Background(), application.StageInventoryImportInput{File: []byte(csv), Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("StageInventoryImport: %v", err)
	}

	res, err := h.svc.CommitStagedInventory(context.Background(), application.CommitStagedInventoryInput{ID: staged.ID, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("CommitStagedInventory: %v", err)
	}
	if res.Status != application.InventoryImportCommitted {
		t.Fatalf("status = %q, want committed", res.Status)
	}
	if res.AssetsCreated != 1 || res.AssetsUpdated != 0 || res.ComponentsCreated != 1 || res.ComponentsUpdated != 0 {
		t.Fatalf("counters a+/a~/c+/c~ = %d/%d/%d/%d, want 1/0/1/0",
			res.AssetsCreated, res.AssetsUpdated, res.ComponentsCreated, res.ComponentsUpdated)
	}
	if res.CommittedAt.IsZero() {
		t.Fatal("committed_at not stamped")
	}
	// The four counters are persisted on the record.
	rec := h.db.imports[0]
	if rec.Status != application.InventoryImportCommitted ||
		rec.AssetsCreated != 1 || rec.ComponentsCreated != 1 || rec.AssetsUpdated != 0 || rec.ComponentsUpdated != 0 {
		t.Fatalf("stored record = %+v, want committed with counters 1/0/1/0", rec)
	}
	// The inventory was written and the commit audited (the I3 command).
	if len(h.db.assets) != 1 {
		t.Fatalf("inventory assets = %d, want 1", len(h.db.assets))
	}
	if !hasAuditAction(h, application.AuditActionInventoryImport) {
		t.Fatal("inventory.import audit event missing")
	}
}

func TestCommitStagedInventoryReCommitIsNoOp(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))
	staged, err := h.svc.StageInventoryImport(context.Background(), application.StageInventoryImportInput{File: []byte(csv), Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("StageInventoryImport: %v", err)
	}
	if _, err := h.svc.CommitStagedInventory(context.Background(), application.CommitStagedInventoryInput{ID: staged.ID, Actor: userActor("admin")}); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	audits := len(h.db.auditEvents)
	txs := len(h.runner.txs)

	res, err := h.svc.CommitStagedInventory(context.Background(), application.CommitStagedInventoryInput{ID: staged.ID, Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("re-commit: %v", err)
	}
	if res.Status != application.InventoryImportCommitted {
		t.Fatalf("re-commit status = %q, want committed", res.Status)
	}
	if res.AssetsCreated != 1 || res.ComponentsCreated != 1 {
		t.Fatalf("re-commit counters = %d/%d, want the stored 1/1", res.AssetsCreated, res.ComponentsCreated)
	}
	// The no-op re-runs neither the I3 command nor its audit: nothing changed.
	if len(h.db.auditEvents) != audits {
		t.Fatalf("re-commit wrote %d extra audit rows, want 0", len(h.db.auditEvents)-audits)
	}
	if len(h.runner.txs) != txs {
		t.Fatalf("re-commit opened %d extra transactions, want 0", len(h.runner.txs)-txs)
	}
}

func TestStagedInventoryImportDeniesNonManager(t *testing.T) {
	h := newHarness(t)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst) // no inventory.manage
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))

	_, err := h.svc.StageInventoryImport(context.Background(), application.StageInventoryImportInput{File: []byte(csv), Actor: userActor("analyst")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("stage by non-manager = %v (%s), want forbidden", err, kind)
	}
	if len(h.db.imports) != 0 {
		t.Fatalf("denied staging persisted %d records, want 0", len(h.db.imports))
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("denied staging opened %d transactions, want 0", len(h.runner.txs))
	}

	if _, err := h.svc.GetInventoryImport(context.Background(), application.GetInventoryImportInput{ID: "import-1", Actor: userActor("analyst")}); err == nil {
		t.Fatal("get import by non-manager must be forbidden")
	}
	if _, err := h.svc.CommitStagedInventory(context.Background(), application.CommitStagedInventoryInput{ID: "import-1", Actor: userActor("analyst")}); err == nil {
		t.Fatal("commit by non-manager must be forbidden")
	}
}

func TestGetInventoryImportNotFound(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	_, err := h.svc.GetInventoryImport(context.Background(), application.GetInventoryImportInput{ID: "nope", Actor: userActor("admin")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("missing import = %v (%s), want not-found", err, kind)
	}
}

// hasAuditAction reports whether the committed audit log holds an event of the
// given action.
func hasAuditAction(h *harness, action string) bool {
	for _, ev := range h.db.auditEvents {
		if ev.Action == action {
			return true
		}
	}
	return false
}
