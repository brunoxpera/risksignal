package application_test

// Unit tests for the export.generate materialisation and the export expiry
// sweep (ARCH-007 §1.2, WP-6.06 / DEV-118): the artifact materialisation and
// generation stamps, the export-id idempotency, the failed-generation record
// and the sweep's artifact deletion + 'expired' mark.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// TestGenerateExportMaterialisesArtifact: the job streams the frozen filter,
// writes the neutralised CSV into the spool, hashes it and stamps the row
// 'completed' with the schema/rule versions and the TTL expiry.
func TestGenerateExportMaterialisesArtifact(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.signalExport.rows = []export.Row{
		{ID: "s1", CveID: "CVE-2026-0001", Priority: "P1", Status: "new", Product: "acme", CreatedAt: fixedNow},
		{ID: "s2", CveID: "CVE-2026-0002", Priority: "P2", Status: "new", Product: "acme", CreatedAt: fixedNow},
		{ID: "s3", CveID: "CVE-2026-0003", Priority: "P2", Status: "new", Product: "other", CreatedAt: fixedNow},
	}

	created, err := h.svc.CreateExport(ctx, application.CreateExportInput{
		Filter: application.ExportFilter{Product: "acme"},
		Format: export.FormatCSV,
		Actor:  systemExportActor("svc"),
	})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}

	res, err := h.svc.GenerateExport(ctx, application.GenerateExportInput{ExportID: created.ExportID})
	if err != nil {
		t.Fatalf("GenerateExport: %v", err)
	}
	if res.Skipped {
		t.Fatal("a pending export was skipped")
	}
	if res.Status != application.ExportStatusCompleted || res.RowCount != 2 {
		t.Fatalf("result = %+v, want completed with 2 rows", res)
	}

	row := h.db.exports[0]
	if row.Status != application.ExportStatusCompleted {
		t.Fatalf("row status = %q, want completed", row.Status)
	}
	if row.RowCount != 2 || row.SizeBytes <= 0 {
		t.Fatalf("stamps = rows %d size %d, want 2 rows and a positive size", row.RowCount, row.SizeBytes)
	}
	if row.SchemaVersion != export.SchemaVersion || row.RuleVersion != domain.PriorityRuleVersionI1b {
		t.Fatalf("versions = %q/%q, want %q/%q", row.SchemaVersion, row.RuleVersion, export.SchemaVersion, domain.PriorityRuleVersionI1b)
	}
	if !row.ExpiresAt.Equal(fixedNow.Add(application.DefaultExportTTL)) {
		t.Fatalf("expires_at = %s, want %s", row.ExpiresAt, fixedNow.Add(application.DefaultExportTTL))
	}
	if row.LastError != "" {
		t.Fatalf("last_error = %q, want cleared", row.LastError)
	}

	data, ok := h.exportStore.artifacts[export.ArtifactKey(created.ExportID, export.FormatCSV)]
	if !ok {
		t.Fatalf("artifact %s was not written", export.ArtifactKey(created.ExportID, export.FormatCSV))
	}
	sum := sha256.Sum256(data)
	if row.Checksum != hex.EncodeToString(sum[:]) {
		t.Fatalf("checksum = %q, want the artifact SHA-256", row.Checksum)
	}
	if row.StoragePath != export.ArtifactKey(created.ExportID, export.FormatCSV) {
		t.Fatalf("storage_path = %q", row.StoragePath)
	}
}

// TestGenerateExportIsIdempotent: a redelivered job on a completed export is a
// no-op — nothing is regenerated.
func TestGenerateExportIsIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.signalExport.rows = []export.Row{{ID: "s1", Priority: "P1", Status: "new", CreatedAt: fixedNow}}

	created, err := h.svc.CreateExport(ctx, application.CreateExportInput{Format: export.FormatJSON, Actor: systemExportActor("svc")})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}
	if _, err := h.svc.GenerateExport(ctx, application.GenerateExportInput{ExportID: created.ExportID}); err != nil {
		t.Fatalf("first GenerateExport: %v", err)
	}
	first := h.db.exports[0]

	res, err := h.svc.GenerateExport(ctx, application.GenerateExportInput{ExportID: created.ExportID})
	if err != nil {
		t.Fatalf("second GenerateExport: %v", err)
	}
	if !res.Skipped {
		t.Fatal("a completed export was regenerated instead of skipped")
	}
	if h.db.exports[0].Checksum != first.Checksum {
		t.Fatal("the completed export was re-stamped")
	}
}

// TestGenerateExportRecordsFailure: a materialisation failure records
// status='failed' + last_error and returns the error.
func TestGenerateExportRecordsFailure(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.signalExport.fail = errors.New("source read failed")

	created, err := h.svc.CreateExport(ctx, application.CreateExportInput{Format: export.FormatCSV, Actor: systemExportActor("svc")})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}
	if _, err := h.svc.GenerateExport(ctx, application.GenerateExportInput{ExportID: created.ExportID}); err == nil {
		t.Fatal("a failing generation returned no error")
	}
	row := h.db.exports[0]
	if row.Status != application.ExportStatusFailed || row.LastError == "" {
		t.Fatalf("row = %+v, want failed with a last_error", row)
	}
}

// TestSweepExportsDeletesArtifactAndMarksExpired: an expired export's artifact
// is deleted and its row flipped 'expired'; an unexpired export is untouched.
func TestSweepExportsDeletesArtifactAndMarksExpired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.exportStore.artifacts["expired.csv"] = []byte("old")
	seedExport(h, application.Export{
		Status: application.ExportStatusCompleted, Format: export.FormatCSV,
		StoragePath: "expired.csv", ExpiresAt: fixedNow.Add(-time.Hour),
	})
	h.exportStore.artifacts["fresh.csv"] = []byte("new")
	seedExport(h, application.Export{
		Status: application.ExportStatusCompleted, Format: export.FormatCSV,
		StoragePath: "fresh.csv", ExpiresAt: fixedNow.Add(time.Hour),
	})

	res, err := h.svc.SweepExports(ctx)
	if err != nil {
		t.Fatalf("SweepExports: %v", err)
	}
	if res.Expired != 1 {
		t.Fatalf("expired = %d, want 1", res.Expired)
	}
	if _, ok := h.exportStore.artifacts["expired.csv"]; ok {
		t.Fatal("the expired artifact was not deleted")
	}
	if _, ok := h.exportStore.artifacts["fresh.csv"]; !ok {
		t.Fatal("the unexpired artifact was deleted")
	}
	statuses := map[string]application.ExportStatus{}
	for _, e := range h.db.exports {
		statuses[e.StoragePath] = e.Status
	}
	if statuses["expired.csv"] != application.ExportStatusExpired {
		t.Fatalf("expired row status = %q, want expired", statuses["expired.csv"])
	}
	if statuses["fresh.csv"] != application.ExportStatusCompleted {
		t.Fatalf("fresh row status = %q, want completed", statuses["fresh.csv"])
	}
}
