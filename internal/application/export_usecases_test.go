package application_test

// Unit tests for the I6 export use cases (ARCH-007 §1.2, WP-6.04 /
// DEV-115): the frozen filter, the atomic export-row + export.generate-job
// write (fault injection rolls the row back), the deny-by-default gate, the
// object-scoped GetExport, the time-limited + audited DownloadExport
// (FakeClock expiry) and the SignalExportSource port contract.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

func systemExportActor(id string) application.Actor {
	return application.Actor{Type: application.ActorTypeSystem, ID: id}
}

func userExportActor(id string) application.Actor {
	return application.Actor{Type: application.ActorTypeUser, ID: id, DisplayName: id}
}

// TestCreateExportFreezesFilterAndEnqueuesJob: the command stores one
// 'pending' export row with the frozen filter and enqueues exactly one
// export.generate outbox job keyed on the export id — atomically.
func TestCreateExportFreezesFilterAndEnqueuesJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	p1 := domain.PriorityP1
	in := application.CreateExportInput{
		Filter: application.ExportFilter{Priority: &p1, Product: "acme"},
		Format: export.FormatCSV,
		Actor:  systemExportActor("svc"),
	}
	res, err := h.svc.CreateExport(ctx, in)
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}
	if res.Status != application.ExportStatusPending {
		t.Fatalf("status = %q, want pending", res.Status)
	}
	if res.ExportID == "" || res.CorrelationID == "" {
		t.Fatalf("empty export id (%q) or correlation id (%q)", res.ExportID, res.CorrelationID)
	}
	if len(h.db.exports) != 1 {
		t.Fatalf("committed exports = %d, want 1", len(h.db.exports))
	}
	row := h.db.exports[0]
	if row.ID != res.ExportID || row.Status != application.ExportStatusPending {
		t.Fatalf("stored row = %+v, want pending id %s", row, res.ExportID)
	}
	if row.Filter.Priority == nil || *row.Filter.Priority != domain.PriorityP1 || row.Filter.Product != "acme" {
		t.Fatalf("frozen filter = %+v, want P1/acme", row.Filter)
	}
	if row.Filter.OwnerID != nil {
		t.Fatalf("owner scope injected for an all/system actor: %v", *row.Filter.OwnerID)
	}
	if row.Format != export.FormatCSV || row.CreatedBy != "svc" {
		t.Fatalf("format/created_by = %q/%q", row.Format, row.CreatedBy)
	}

	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox rows = %d, want 1", len(h.db.outboxEvents))
	}
	ev := h.db.outboxEvents[0]
	if ev.Type != application.EventTypeExportGenerate {
		t.Fatalf("outbox type = %q, want %q", ev.Type, application.EventTypeExportGenerate)
	}
	if ev.DedupeKey != "export.generate:"+res.ExportID {
		t.Fatalf("dedupe key = %q, want export.generate:%s", ev.DedupeKey, res.ExportID)
	}
	var payload struct {
		ExportID string `json:"export_id"`
	}
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if payload.ExportID != res.ExportID {
		t.Fatalf("payload export_id = %q, want %s", payload.ExportID, res.ExportID)
	}
}

// TestCreateExportInjectsOwnerScopeForAssignedGrant: an `assigned`-scope
// principal's export is frozen to its own signals (owner_id = principal.id),
// whatever the request asked for.
func TestCreateExportInjectsOwnerScopeForAssignedGrant(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)

	other := "someone-else"
	_, err := h.svc.CreateExport(ctx, application.CreateExportInput{
		Filter: application.ExportFilter{OwnerID: &other},
		Format: export.FormatJSON,
		Actor:  userExportActor("resp"),
	})
	if err != nil {
		t.Fatalf("CreateExport: %v", err)
	}
	if len(h.db.exports) != 1 {
		t.Fatalf("committed exports = %d, want 1", len(h.db.exports))
	}
	got := h.db.exports[0].Filter.OwnerID
	if got == nil || *got != "resp" {
		t.Fatalf("frozen owner = %v, want resp (the assigned principal)", got)
	}
}

// TestCreateExportRollsBackOnFailedJobAppend: the ARCH-001 §5 fault seam — a
// failing export.generate append rolls the export row back with it, so no
// export can exist without its job.
func TestCreateExportRollsBackOnFailedJobAppend(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.outbox.failpoint = errors.New("outbox append failed")

	_, err := h.svc.CreateExport(ctx, application.CreateExportInput{
		Filter: application.ExportFilter{},
		Format: export.FormatCSV,
		Actor:  systemExportActor("svc"),
	})
	if err == nil {
		t.Fatal("CreateExport accepted a failing job append")
	}
	if len(h.db.exports) != 0 {
		t.Fatalf("committed exports = %d, want 0 (row must roll back)", len(h.db.exports))
	}
	if len(h.db.outboxEvents) != 0 {
		t.Fatalf("committed outbox rows = %d, want 0", len(h.db.outboxEvents))
	}
	if last := h.runner.last(); last == nil || !last.rolledBack {
		t.Fatal("the transaction was not rolled back")
	}
}

// TestCreateExportDeniedWritesNothing: deny-by-default — a principal without
// exports.create is refused before any transaction, row or audit.
func TestCreateExportDeniedWritesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("norole", "No Role") // no roles ⇒ deny-by-default

	_, err := h.svc.CreateExport(ctx, application.CreateExportInput{
		Filter: application.ExportFilter{},
		Format: export.FormatCSV,
		Actor:  userExportActor("norole"),
	})
	if err == nil {
		t.Fatal("CreateExport accepted a role-less principal")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("error kind = %s, want forbidden", kind)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("a denied command opened %d transactions, want 0", len(h.runner.txs))
	}
	if len(h.db.exports) != 0 || len(h.db.outboxEvents) != 0 || len(h.db.auditEvents) != 0 {
		t.Fatal("a denied command wrote state")
	}
}

// TestCreateExportRejectsInvalidFilterAndFormat: the bounded filter and the
// format vocabulary are validated before the transaction.
func TestCreateExportRejectsInvalidFilterAndFormat(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	badPriority := domain.Priority("P9")
	badStatus := domain.SignalStatus("resolved_typo")
	badAsset := domain.AssetType("mainframe")
	badSLA := application.ExportSLAState("stale")
	from := fixedNow
	to := fixedNow.Add(-time.Hour) // from after to ⇒ empty/invalid window

	cases := []struct {
		name string
		f    application.ExportFilter
		fmt  export.Format
	}{
		{"format", application.ExportFilter{}, export.Format("xml")},
		{"priority", application.ExportFilter{Priority: &badPriority}, export.FormatCSV},
		{"status", application.ExportFilter{Status: &badStatus}, export.FormatCSV},
		{"asset_type", application.ExportFilter{AssetType: &badAsset}, export.FormatCSV},
		{"sla_state", application.ExportFilter{SLAState: &badSLA}, export.FormatCSV},
		{"created_window", application.ExportFilter{CreatedFrom: &from, CreatedTo: &to}, export.FormatCSV},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.CreateExport(ctx, application.CreateExportInput{
				Filter: tc.f, Format: tc.fmt, Actor: systemExportActor("svc"),
			})
			if err == nil {
				t.Fatalf("%s: accepted an invalid input", tc.name)
			}
			if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
				t.Fatalf("%s: error kind = %s, want validation", tc.name, kind)
			}
		})
	}
	if len(h.db.exports) != 0 || len(h.runner.txs) != 0 {
		t.Fatal("an invalid create wrote state or opened a transaction")
	}
}

// TestGetExportObjectScope: an all-scope role reads any export, an
// `assigned` role only its own; a role-less principal is denied and an
// unknown id is not-found.
func TestGetExportObjectScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)
	h.users.add("analyst", "Analyst", domain.RoleSecurityAnalyst)
	h.users.add("norole", "No Role")

	mine := seedExport(h, application.Export{CreatedBy: "resp"})
	theirs := seedExport(h, application.Export{CreatedBy: "other"})

	// The assigned principal reads its own export.
	if got, err := h.svc.GetExport(ctx, application.GetExportInput{ExportID: mine.ID, Actor: userExportActor("resp")}); err != nil || got.ID != mine.ID {
		t.Fatalf("GetExport(own) = %+v, %v", got, err)
	}
	// ... but not somebody else's.
	if _, err := h.svc.GetExport(ctx, application.GetExportInput{ExportID: theirs.ID, Actor: userExportActor("resp")}); err == nil {
		t.Fatal("assigned principal read another's export")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("cross-owner error kind = %s, want forbidden", kind)
	}
	// The all-scope analyst reads any export.
	if _, err := h.svc.GetExport(ctx, application.GetExportInput{ExportID: theirs.ID, Actor: userExportActor("analyst")}); err != nil {
		t.Fatalf("analyst read = %v", err)
	}
	// Deny-by-default and not-found.
	if _, err := h.svc.GetExport(ctx, application.GetExportInput{ExportID: mine.ID, Actor: userExportActor("norole")}); err == nil {
		t.Fatal("role-less principal read an export")
	}
	if _, err := h.svc.GetExport(ctx, application.GetExportInput{ExportID: "missing", Actor: userExportActor("analyst")}); err == nil {
		t.Fatal("unknown id accepted")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("unknown-id error kind = %s, want not_found", kind)
	}
}

// TestDownloadExportStreamsAndAudits: a completed, unexpired export streams
// its artifact and appends one audit event.
func TestDownloadExportStreamsAndAudits(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)

	body := []byte("id,cve_id\n1,CVE-2024-0001\n")
	row := seedExport(h, application.Export{
		Status:      application.ExportStatusCompleted,
		Format:      export.FormatCSV,
		CreatedBy:   "resp",
		StoragePath: "art-1.csv",
		SizeBytes:   int64(len(body)),
		ExpiresAt:   fixedNow.Add(24 * time.Hour),
	})
	h.exportStore.artifacts[row.StoragePath] = body

	res, err := h.svc.DownloadExport(ctx, application.DownloadExportInput{ExportID: row.ID, Actor: userExportActor("resp")})
	if err != nil {
		t.Fatalf("DownloadExport: %v", err)
	}
	defer func() { _ = res.Reader.Close() }()
	got, err := io.ReadAll(res.Reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("streamed %q, want %q", got, body)
	}
	if res.ContentType != "text/csv; charset=utf-8" || res.Filename != "export-"+row.ID+".csv" {
		t.Fatalf("content-type/filename = %q/%q", res.ContentType, res.Filename)
	}
	if len(h.db.auditEvents) != 1 || h.db.auditEvents[0].Action != application.EventTypeExportDownloaded {
		t.Fatalf("audit = %+v, want one export.downloaded", h.db.auditEvents)
	}
	if h.db.auditEvents[0].AggregateType != application.AuditAggregateExport || h.db.auditEvents[0].AggregateID != row.ID {
		t.Fatalf("audit aggregate = %s/%s, want export/%s", h.db.auditEvents[0].AggregateType, h.db.auditEvents[0].AggregateID, row.ID)
	}
}

// TestDownloadExportExpiryViaFakeClock: the download is time-limited — past
// expires_at it is refused (and writes no audit), exactly at expires_at it is
// already expired.
func TestDownloadExportExpiryViaFakeClock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)

	body := []byte("{}")
	row := seedExport(h, application.Export{
		Status:      application.ExportStatusCompleted,
		Format:      export.FormatJSON,
		CreatedBy:   "resp",
		StoragePath: "art-2.json",
		ExpiresAt:   fixedNow.Add(time.Hour),
	})
	h.exportStore.artifacts[row.StoragePath] = body

	// Exactly at the expiry boundary: already expired (now >= expires_at).
	h.clock.Set(row.ExpiresAt)
	txsBefore := len(h.runner.txs)
	if _, err := h.svc.DownloadExport(ctx, application.DownloadExportInput{ExportID: row.ID, Actor: userExportActor("resp")}); err == nil {
		t.Fatal("download accepted at the expiry boundary")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("expired error kind = %s, want conflict", kind)
	}
	if len(h.runner.txs) != txsBefore {
		t.Fatal("an expired download opened a transaction")
	}
	if len(h.db.auditEvents) != 0 {
		t.Fatal("an expired download wrote an audit row")
	}

	// One second before expiry: allowed.
	h.clock.Set(row.ExpiresAt.Add(-time.Second))
	res, err := h.svc.DownloadExport(ctx, application.DownloadExportInput{ExportID: row.ID, Actor: userExportActor("resp")})
	if err != nil {
		t.Fatalf("download one second before expiry: %v", err)
	}
	_ = res.Reader.Close()
	if len(h.db.auditEvents) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(h.db.auditEvents))
	}
}

// TestDownloadExportRejectsNotCompletedAndDenied: a pending export has no
// artifact, and a denied principal streams nothing — neither writes an audit.
func TestDownloadExportRejectsNotCompletedAndDenied(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)
	h.users.add("norole", "No Role")

	pending := seedExport(h, application.Export{Status: application.ExportStatusPending, CreatedBy: "resp"})
	if _, err := h.svc.DownloadExport(ctx, application.DownloadExportInput{ExportID: pending.ID, Actor: userExportActor("resp")}); err == nil {
		t.Fatal("download accepted a pending export")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindConflict {
		t.Fatalf("pending error kind = %s, want conflict", kind)
	}

	done := seedExport(h, application.Export{
		Status: application.ExportStatusCompleted, CreatedBy: "resp",
		StoragePath: "a.csv", ExpiresAt: fixedNow.Add(time.Hour),
	})
	h.exportStore.artifacts["a.csv"] = []byte("x")
	if _, err := h.svc.DownloadExport(ctx, application.DownloadExportInput{ExportID: done.ID, Actor: userExportActor("norole")}); err == nil {
		t.Fatal("role-less principal downloaded an export")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("denied download error kind = %s, want forbidden", kind)
	}
	if len(h.db.auditEvents) != 0 {
		t.Fatal("a refused download wrote an audit row")
	}
}

// TestSignalExportSourceFilteredOrdered pins the port contract: the source
// returns the filtered rows ordered by the §10.4 sort (priority, then the
// next SLA deadline with no-deadline rows last, then created_at, then id).
func TestSignalExportSourceFilteredOrdered(t *testing.T) {
	ctx := context.Background()
	base := fixedNow
	d1 := base.Add(time.Hour)
	d2 := base.Add(2 * time.Hour)

	src := &fakeSignalExportSource{rows: []export.Row{
		{ID: "s-p4", Priority: "P4", AssetID: "a1", Owner: "resp", CreatedAt: base},
		{ID: "s-p1-late", Priority: "P1", AssetID: "a1", Owner: "resp", DueAt: &d2, CreatedAt: base},
		{ID: "s-p1-none", Priority: "P1", AssetID: "a1", Owner: "other", CreatedAt: base},
		{ID: "s-p1-early", Priority: "P1", AssetID: "a1", Owner: "resp", DueAt: &d1, CreatedAt: base},
	}}
	p1 := domain.PriorityP1
	var owner = "resp"
	rows, err := src.Scan(ctx, application.ExportFilter{Priority: &p1, OwnerID: &owner}, base)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	gotIDs := make([]string, len(rows))
	for i, r := range rows {
		gotIDs[i] = r.ID
	}
	want := []string{"s-p1-early", "s-p1-late"} // P1, owned by resp, earliest deadline first
	if len(gotIDs) != len(want) {
		t.Fatalf("rows = %v, want %v", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("rows = %v, want %v", gotIDs, want)
		}
	}
}

// TestSignalExportSourceConsumesFrozenFilter ties the two halves together:
// the filter CreateExport froze (owner-scoped for an assigned principal) is
// exactly the filter the export source scans with.
func TestSignalExportSourceConsumesFrozenFilter(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.users.add("resp", "Resp", domain.RoleSystemResponsible)

	if _, err := h.svc.CreateExport(ctx, application.CreateExportInput{
		Filter: application.ExportFilter{Product: "acme"},
		Format: export.FormatCSV,
		Actor:  userExportActor("resp"),
	}); err != nil {
		t.Fatalf("CreateExport: %v", err)
	}
	frozen := h.db.exports[0].Filter

	src := &fakeSignalExportSource{rows: []export.Row{
		{ID: "own-acme", Owner: "resp", Product: "acme"},
		{ID: "own-other", Owner: "resp", Product: "other"},
		{ID: "theirs-acme", Owner: "other", Product: "acme"},
	}}
	rows, err := src.Scan(ctx, frozen, fixedNow)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "own-acme" {
		t.Fatalf("scan of the frozen filter = %v, want only own-acme", rows)
	}
}
