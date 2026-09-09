package main

// Integration tests of the WP-2.03b extended existing-table sqlc queries
// (DEV-038) at the composition root, on a real short-lived PostgreSQL.
//
// The queries under test are the I2 extensions of the I1b tables (ARCH-002
// §1/§3, migration 00004):
//
//   * source_runs cursor bookkeeping — cursor_before is written when the run
//     opens, cursor_after only by the success path of CompleteSourceRun: the
//     test proves the read/write round trip and the invariant that a failed
//     run never advances the cursor (the CASE guard in the generated SQL
//     forces cursor_after NULL on any terminal status other than
//     'succeeded' — the cursor advances only after the commit of a
//     successful run, ch. 6.1).
//   * the extended vulnerabilities upsert — description / cvss / "references"
//     / cpe_config join the natural-key upsert (the reserved keyword is
//     quoted as "references" in every SQL statement); the test upserts a
//     record carrying all four NVD fields, reads it back through
//     GetVulnerabilityByCveID, then refreshes it and asserts the semantics:
//     same row id (UQ cve_id), published_at kept at the original, the NVD
//     fields following the latest statement, cpe_config returning to NULL
//     when the refresh carries none.
//   * the bytea raw-record insert — a payload of bytes that are not valid
//     UTF-8 round trips through the bytea column unchanged, together with
//     its self-describing content_encoding ('gzip' | 'json' | NULL).
//   * the extended evidence vocabulary — the type column is plain text and
//     the insert is type-agnostic, so the I2 types nvd_statement /
//     reference / kev_removed flow through the unchanged InsertEvidence and
//     deduplicate on the natural key (raw_record_id, type, value_hash) like
//     the I1b types; the test inserts one of each and counts them back.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
)

// decodeJSON parses a jsonb round-trip value into plain Go structures so the
// assertions compare values, not the normalized byte representation.
func decodeJSON(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode json %q: %v", data, err)
	}
	return v
}

func TestSourceRunCursorsReadWriteAndAdvanceOnlyOnSuccess(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type: "nvd", Name: "cursor-source", Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}

	// The run opens from the cursor the fetch half read off the source; the
	// open write persists it as cursor_before (ARCH-002 §1: the cursor value
	// when the run opened).
	windowStart := mustTS(t, "2026-09-09T08:00:00Z")
	before := []byte(`{"last_modified":"2026-09-09T08:00:00Z"}`)
	run, err := q.CreateSourceRun(ctx, gen.CreateSourceRunParams{
		SourceID: sourceID, StartedAt: windowStart, CursorBefore: before,
	})
	if err != nil {
		t.Fatalf("CreateSourceRun: %v", err)
	}
	if run.Status != "running" || !reflect.DeepEqual(decodeJSON(t, run.CursorBefore), decodeJSON(t, before)) || run.CursorAfter != nil {
		t.Fatalf("CreateSourceRun = %+v, want running with cursor_before %s and no cursor_after", run, before)
	}

	// The generated read returns the run with its cursor fields. The cursor
	// is jsonb: the database re-renders it canonically, so the round trip is
	// compared semantically, never byte-wise.
	opened, err := q.GetSourceRunByID(ctx, run.ID)
	if err != nil || opened.ID != run.ID || !reflect.DeepEqual(decodeJSON(t, opened.CursorBefore), decodeJSON(t, before)) || opened.CursorAfter != nil {
		t.Fatalf("GetSourceRunByID after open = %+v, %v; want cursor_before kept, cursor_after NULL", opened, err)
	}

	// A failed run closes with its error text and counters — and cursor_after
	// NULL even though a cursor value is passed: the cursor advances only
	// after the commit of a successful run (ch. 6.1), so the next run starts
	// again from cursor_before.
	failedAt := mustTS(t, "2026-09-09T09:00:00Z")
	failed, err := q.CompleteSourceRun(ctx, gen.CompleteSourceRunParams{
		ID: run.ID, FinishedAt: failedAt, Status: "failed",
		Counters: []byte(`{"records": 0, "normalized": 0, "errors": 1}`),
		Error:    pgtype.Text{String: "fetch.http_503: upstream unavailable", Valid: true},
		// A caller bug must not move the cursor: pass a bogus cursor_after.
		CursorAfter: []byte(`{"last_modified":"2099-01-01T00:00:00Z"}`),
	})
	if err != nil {
		t.Fatalf("CompleteSourceRun(failed): %v", err)
	}
	if failed.Status != "failed" || failed.CursorAfter != nil ||
		failed.Error.String != "fetch.http_503: upstream unavailable" {
		t.Fatalf("CompleteSourceRun(failed) = %+v, want failed with error and cursor_after NULL (guard)", failed)
	}
	closed, err := q.GetSourceRunByID(ctx, run.ID)
	if err != nil || closed.Status != "failed" || closed.CursorAfter != nil ||
		!reflect.DeepEqual(decodeJSON(t, closed.CursorBefore), decodeJSON(t, before)) {
		t.Fatalf("GetSourceRunByID after failed close = %+v, %v; want failed, cursor_after NULL, cursor_before kept", closed, err)
	}

	// The next run re-opens from the same cursor_before and succeeds: only
	// now is the cursor_after committed (ch. 8.2: cursor_after.last_modified
	// = window.To persisted after the successful, fully-committed run).
	run2, err := q.CreateSourceRun(ctx, gen.CreateSourceRunParams{
		SourceID: sourceID, StartedAt: failedAt, CursorBefore: before,
	})
	if err != nil {
		t.Fatalf("second CreateSourceRun: %v", err)
	}
	after := []byte(`{"last_modified":"2026-09-09T10:00:00Z"}`)
	succeededAt := mustTS(t, "2026-09-09T10:00:05Z")
	succeeded, err := q.CompleteSourceRun(ctx, gen.CompleteSourceRunParams{
		ID: run2.ID, FinishedAt: succeededAt, Status: "succeeded",
		Counters:    []byte(`{"records": 1, "normalized": 2, "errors": 0}`),
		CursorAfter: after,
	})
	if err != nil {
		t.Fatalf("CompleteSourceRun(succeeded): %v", err)
	}
	if succeeded.Status != "succeeded" || !reflect.DeepEqual(decodeJSON(t, succeeded.CursorAfter), decodeJSON(t, after)) || succeeded.Error.Valid {
		t.Fatalf("CompleteSourceRun(succeeded) = %+v, want succeeded with cursor_after %s and no error", succeeded, after)
	}
	final, err := q.GetSourceRunByID(ctx, run2.ID)
	if err != nil || !reflect.DeepEqual(decodeJSON(t, final.CursorAfter), decodeJSON(t, after)) ||
		!reflect.DeepEqual(decodeJSON(t, final.CursorBefore), decodeJSON(t, before)) ||
		!final.FinishedAt.Valid || final.FinishedAt.Time != succeededAt.Time {
		t.Fatalf("GetSourceRunByID after success = %+v, %v; want committed cursor_after and the run closed at %v", final, err, succeededAt.Time)
	}
}

func TestExtendedVulnerabilityUpsertRoundTripsNvdFields(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	published := mustTS(t, "2024-01-15T00:00:00Z")
	modified := mustTS(t, "2026-09-01T00:00:00Z")
	description := "Heap-based buffer overflow in acme widget's parser"
	cvss := `{"version":"3.1","base_score":9.8,"base_severity":"critical","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}`
	refs := `[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2024-9999","source":"nvd"},{"url":"https://github.com/acme/widget/security/advisories/GHSA-0000-0000-0000","source":"github"}]`
	cpe := `{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:2.4:*:*:*:*:*:*:*"}]}]}`

	// The extended upsert carries description, cvss, the quoted "references"
	// and cpe_config alongside the I1b identity + summary fields.
	id, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:         "CVE-2024-9999",
		Summary:       "first summary",
		Description:   pgtype.Text{String: description, Valid: true},
		PublishedAt:   published,
		ModifiedAt:    modified,
		Cvss:          []byte(cvss),
		NvdReferences: []byte(refs),
		CpeConfig:     []byte(cpe),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}

	row, err := q.GetVulnerabilityByCveID(ctx, "CVE-2024-9999")
	if err != nil {
		t.Fatalf("GetVulnerabilityByCveID: %v", err)
	}
	if row.ID != id {
		t.Fatalf("read back id = %v, want the upserted id %v", row.ID, id)
	}
	if row.Summary != "first summary" || !row.Description.Valid || row.Description.String != description {
		t.Fatalf("summary/description = %q/%q, want first summary / %q", row.Summary, row.Description.String, description)
	}
	if !reflect.DeepEqual(decodeJSON(t, row.Cvss), decodeJSON(t, []byte(cvss))) {
		t.Fatalf("cvss round trip = %s, want %s", row.Cvss, cvss)
	}
	gotRefs, ok := decodeJSON(t, row.References).([]any)
	if !ok || len(gotRefs) != 2 {
		t.Fatalf("references round trip = %s, want a 2-element array", row.References)
	}
	first, ok := gotRefs[0].(map[string]any)
	if !ok || first["url"] != "https://nvd.nist.gov/vuln/detail/CVE-2024-9999" {
		t.Fatalf("references[0] = %v, want the nvd url", gotRefs[0])
	}
	if !reflect.DeepEqual(decodeJSON(t, row.CpeConfig), decodeJSON(t, []byte(cpe))) {
		t.Fatalf("cpe_config round trip = %s, want %s", row.CpeConfig, cpe)
	}

	// A refresh by the same natural key returns the same row id, keeps the
	// original published_at and follows the latest statement for summary,
	// description and the NVD fields; a refresh carrying no cpe_config sets
	// it back to NULL (a statement only writes what it carries).
	modified2 := mustTS(t, "2026-09-08T00:00:00Z")
	refreshedID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:         "CVE-2024-9999",
		Summary:       "second summary",
		Description:   pgtype.Text{String: "updated description", Valid: true},
		PublishedAt:   mustTS(t, "2099-01-01T00:00:00Z"), // must be ignored on refresh
		ModifiedAt:    modified2,
		Cvss:          []byte(`{"version":"3.1","base_score":9.1,"base_severity":"critical","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}`),
		NvdReferences: []byte(`[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2024-9999","source":"nvd"}]`),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability(refresh): %v", err)
	}
	if refreshedID != id {
		t.Fatalf("refresh id = %v, want the original id %v (UQ cve_id)", refreshedID, id)
	}
	row, err = q.GetVulnerabilityByCveID(ctx, "CVE-2024-9999")
	if err != nil {
		t.Fatalf("GetVulnerabilityByCveID after refresh: %v", err)
	}
	if row.PublishedAt.Time != published.Time {
		t.Fatalf("published_at after refresh = %v, want the original %v (kept on refresh, ch. 8.2)", row.PublishedAt.Time, published.Time)
	}
	if row.Summary != "second summary" || row.Description.String != "updated description" {
		t.Fatalf("after refresh summary/description = %q/%q, want second summary / updated description", row.Summary, row.Description.String)
	}
	gotRefs, ok = decodeJSON(t, row.References).([]any)
	if !ok || len(gotRefs) != 1 {
		t.Fatalf("references after refresh = %s, want a 1-element array", row.References)
	}
	if row.Cvss == nil || row.CpeConfig != nil {
		t.Fatalf("after refresh cvss/cpe_config = %v/%v, want cvss refreshed and cpe_config NULL (refresh carries none)", row.Cvss, row.CpeConfig)
	}

	// A skeleton upsert (I1b shape, and the I2 KEV shape before NVD arrives,
	// ARCH-002 §2.2) carries identity + summary only: the NVD fields stay
	// NULL and the row is valid.
	skeletonAt := mustTS(t, "2026-09-09T09:00:00Z")
	skeletonID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: "CVE-2026-0001", Summary: "kev skeleton", PublishedAt: skeletonAt, ModifiedAt: skeletonAt,
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability(skeleton): %v", err)
	}
	skeleton, err := q.GetVulnerabilityByCveID(ctx, "CVE-2026-0001")
	if err != nil || skeleton.ID != skeletonID {
		t.Fatalf("GetVulnerabilityByCveID(skeleton) = %+v, %v; want the skeleton row", skeleton, err)
	}
	if skeleton.Description.Valid || skeleton.Cvss != nil || skeleton.References != nil || skeleton.CpeConfig != nil {
		t.Fatalf("skeleton NVD fields = %+v, want all NULL", skeleton)
	}
}

func TestRawRecordByteaPayloadAndContentEncodingRoundTrip(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type: "epss", Name: "bytea-source", Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	fetched := mustTS(t, "2026-09-09T09:00:05Z")

	// The EPSS raw record is the compressed file: payload bytes that are not
	// valid UTF-8 (0x1f 0x8b gzip magic plus arbitrary high bytes) prove the
	// bytea column stores and returns the exact bytes, and content_encoding
	// = 'gzip' makes them self-describing for reprocess (ADR-013, ARCH-002
	// §2.3/§3).
	gzipDoc := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xed, 0xc1, 0x31, 0x0d, 0x00, 0x00, 0x00, 0x0c, 0x20, 0xfb, 0xa7, 0xd6, 0xbf, 0xa7, 0x60, 0xfe, 0xff, 0x00}
	id, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "epss_scores-2026-09-09.csv.gz",
		ContentHash: testHash('g'), Payload: gzipDoc,
		ContentEncoding: pgtype.Text{String: "gzip", Valid: true},
		FetchedAt:       fetched,
	})
	if err != nil {
		t.Fatalf("InsertRawRecord(gzip): %v", err)
	}

	row, err := q.GetRawRecordByID(ctx, id)
	if err != nil {
		t.Fatalf("GetRawRecordByID: %v", err)
	}
	if !bytes.Equal(row.Payload, gzipDoc) {
		t.Fatalf("payload round trip = %v, want the exact bytea %v", row.Payload, gzipDoc)
	}
	if !row.ContentEncoding.Valid || row.ContentEncoding.String != "gzip" {
		t.Fatalf("content_encoding = %v, want gzip", row.ContentEncoding)
	}

	// Natural-key idempotency: re-inserting the identical document (same
	// source, external_id, content_hash) returns the same row id and stores
	// no duplicate.
	if again, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "epss_scores-2026-09-09.csv.gz",
		ContentHash: testHash('g'), Payload: gzipDoc,
		ContentEncoding: pgtype.Text{String: "gzip", Valid: true},
		FetchedAt:       fetched,
	}); err != nil || again != id {
		t.Fatalf("re-insert id = %v, %v; want the existing id %v", again, err, id)
	}

	// A 'json'-encoded document (the synthetic shape) and a NULL
	// content_encoding (the I1b insert path, which does not set it) round
	// trip too.
	jsonDoc := []byte(`{"cases": [{"cve_id": "CVE-2024-9001"}]}`)
	jsonID, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "synthetic-doc",
		ContentHash: testHash('j'), Payload: jsonDoc,
		ContentEncoding: pgtype.Text{String: "json", Valid: true},
		FetchedAt:       fetched,
	})
	if err != nil {
		t.Fatalf("InsertRawRecord(json): %v", err)
	}
	jsonRow, err := q.GetRawRecordByID(ctx, jsonID)
	if err != nil || !bytes.Equal(jsonRow.Payload, jsonDoc) || jsonRow.ContentEncoding.String != "json" {
		t.Fatalf("json row = %+v, %v; want the exact bytes with content_encoding json", jsonRow, err)
	}

	nilID, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "i1b-shaped-doc",
		ContentHash: testHash('i'), Payload: jsonDoc, FetchedAt: fetched,
	})
	if err != nil {
		t.Fatalf("InsertRawRecord(no encoding): %v", err)
	}
	nilRow, err := q.GetRawRecordByID(ctx, nilID)
	if err != nil || nilRow.ContentEncoding.Valid {
		t.Fatalf("no-encoding row = %+v, %v; want content_encoding NULL", nilRow, err)
	}
}

func TestEvidenceInsertAcceptsI2VocabularyTypes(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	// Seed the rows the evidence foreign keys point at: one source, one run,
	// one raw record and one skeleton vulnerability (the coupling point KEV
	// arrives before NVD through, ARCH-002 §2.2).
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type: "kev", Name: "vocab-source", Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	at := mustTS(t, "2026-09-09T09:00:05Z")
	if _, err := q.CreateSourceRun(ctx, gen.CreateSourceRunParams{
		SourceID: sourceID, StartedAt: at,
	}); err != nil {
		t.Fatalf("CreateSourceRun: %v", err)
	}
	rawID, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "kev-2026-09-09.json",
		ContentHash: testHash('k'), Payload: []byte(`{"catalogVersion": "2026-09-09"}`),
		ContentEncoding: pgtype.Text{String: "json", Valid: true},
		FetchedAt:       at,
	})
	if err != nil {
		t.Fatalf("InsertRawRecord: %v", err)
	}
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: "CVE-2024-9999", Summary: "skeleton before nvd", PublishedAt: at, ModifiedAt: at,
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}

	// The I2 evidence types (ARCH-002 §1/§2: nvd_statement, reference,
	// kev_removed) flow through the unchanged InsertEvidence statement — the
	// type column is plain text, so no per-type SQL exists — and deduplicate
	// on the natural key (raw_record_id, type, value_hash).
	nvdStatement := []byte(`{"cve_id": "CVE-2024-9999", "statement": "Heap-based buffer overflow in acme widget's parser (canonical NVD record excerpt)"}`)
	reference := []byte(`{"cve_id": "CVE-2024-9999", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999", "source": "nvd"}`)
	kevRemoved := []byte(`{"cve_id": "CVE-2024-9999", "vendor": "acme", "product": "widget", "removed_from_catalog_at": "2026-09-09"}`)
	evidences := []struct {
		typ   string
		value []byte
		hash  byte
	}{
		{"nvd_statement", nvdStatement, 'n'},
		{"reference", reference, 'r'},
		{"kev_removed", kevRemoved, 'm'},
	}
	for _, ev := range evidences {
		params := gen.InsertEvidenceParams{
			VulnerabilityID: vulnID,
			RawRecordID:     rawID,
			Type:            ev.typ,
			Value:           ev.value,
			ValueHash:       testHash(ev.hash),
			ObservedAt:      at,
		}
		evidenceID, err := q.InsertEvidence(ctx, params)
		if err != nil {
			t.Fatalf("InsertEvidence(%s): %v", ev.typ, err)
		}
		// A repeated statement is a no-op on the natural key — inserting the
		// same (raw_record_id, type, value_hash) again must not error, must
		// not duplicate the row and must return the already existing id
		// (ARCH-003 §7: new-or-existing evidence id).
		again, err := q.InsertEvidence(ctx, params)
		if err != nil || again != evidenceID {
			t.Fatalf("InsertEvidence(%s) re-insert = %v, %v; want the same evidence id %v", ev.typ, again, err, evidenceID)
		}
	}

	// The evidence table is insert-only on this query surface (no evidence
	// read query exists yet), so the stored rows are counted back directly:
	// exactly one row per new type landed, and the repeated inserts added
	// nothing.
	for _, ev := range evidences {
		var n int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM evidences WHERE vulnerability_id = $1 AND type = $2`,
			vulnID, ev.typ).Scan(&n); err != nil {
			t.Fatalf("count evidences(type=%s): %v", ev.typ, err)
		}
		if n != 1 {
			t.Fatalf("evidences of type %s = %d, want exactly 1 (dedupe on (raw_record_id, type, value_hash))", ev.typ, n)
		}
	}
	var total int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM evidences WHERE vulnerability_id = $1`, vulnID).Scan(&total); err != nil {
		t.Fatalf("count evidences total: %v", err)
	}
	if total != int64(len(evidences)) {
		t.Fatalf("total evidences = %d, want %d (each new type stored once)", total, len(evidences))
	}
}
