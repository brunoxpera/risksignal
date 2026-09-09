package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// fakeBulkWriter is the unit-test double of the BulkRowWriter the source-run
// wiring hands the EPSS adapter (application.BulkRowWriter): it records
// every streamed row in arrival order. failAfter makes the writer fail on
// the n-th row — the infrastructure-failure seam of the pass.
type fakeBulkWriter struct {
	rows      []application.EpssRow
	failAfter int // 0: never fail
}

func (f *fakeBulkWriter) WriteEpssRow(_ context.Context, row application.EpssRow) error {
	if f.failAfter > 0 && len(f.rows) >= f.failAfter {
		return errors.New("boom: bulk write failed")
	}
	f.rows = append(f.rows, row)
	return nil
}

// fakeSink records the RecordError emissions of a pass. The domain-object
// methods are the EPSS deviation's unused path (EPSS emits no
// Vulnerability/Evidence); a call is recorded so the tests can assert the
// bulk path never touches them.
type fakeSink struct {
	errs   []application.RecordError
	events []string
}

func (f *fakeSink) Vulnerability(_ context.Context, v domain.Vulnerability) error {
	f.events = append(f.events, "vulnerability:"+v.CVEID)
	return nil
}

func (f *fakeSink) Evidence(_ context.Context, e domain.Evidence) error {
	f.events = append(f.events, "evidence:"+string(e.Type))
	return nil
}

func (f *fakeSink) RecordError(_ context.Context, e application.RecordError) error {
	f.errs = append(f.errs, e)
	f.events = append(f.events, "error:"+e.Reason)
	return nil
}

// assertNoDomainEmissions fails the test when the pass touched the
// domain-object sink methods — the EPSS specialisation streams bulk rows
// only (ARCH-002 §1: its output is epss_current rows, not domain objects).
func assertNoDomainEmissions(t *testing.T, f *fakeSink) {
	t.Helper()
	for _, ev := range f.events {
		if strings.HasPrefix(ev, "vulnerability:") || strings.HasPrefix(ev, "evidence:") {
			t.Errorf("the EPSS pass touched the domain-object sink: %s", ev)
		}
	}
}

// runNormalize runs one pass over the gzip-compressed payload and fails the
// test on an unexpected error.
func runNormalize(t *testing.T, csvText string, bulk *fakeBulkWriter) (*fakeBulkWriter, *fakeSink, application.NormalizeResult) {
	t.Helper()
	in := application.NormalizeInput{
		RawRecordID: "raw-epss-1",
		Payload:     gzipBytes(t, csvText),
		ContentHash: "fixture",
		EpssBulk:    bulk,
	}
	f := &fakeSink{}
	res, err := new(Adapter).Normalize(context.Background(), in, f)
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}
	return bulk, f, res
}

// TestNormalizeStreamsFixtureRowsIntoBulkWriter drives one pass over the
// daily-file fixture (comment + header + three data rows): the three rows
// are streamed into the bulk writer in file order with their exact values
// (the row-count read of the fixture) and nothing else — the comment and
// header lines never reach the writer.
func TestNormalizeStreamsFixtureRowsIntoBulkWriter(t *testing.T) {
	bulk, f, res := runNormalize(t, epssCSV, &fakeBulkWriter{})

	if res.Errors != 0 {
		t.Errorf("NormalizeResult.Errors = %d, want 0", res.Errors)
	}
	if want := 3; res.Records != want {
		t.Errorf("NormalizeResult.Records = %d, want %d (the fixture's data-row count)", res.Records, want)
	}

	want := []application.EpssRow{
		{CveID: "CVE-2026-0001", Score: "0.97368", Percentile: "0.9991"},
		{CveID: "CVE-2026-0002", Score: "0.00510", Percentile: "0.4021"},
		{CveID: "CVE-2026-0003", Score: "0.00057", Percentile: "0.1937"},
	}
	if !reflect.DeepEqual(bulk.rows, want) {
		t.Errorf("streamed rows = %+v, want %+v (file order, exact literals)", bulk.rows, want)
	}
	if len(f.errs) != 0 {
		t.Errorf("a clean fixture isolated %d records: %+v", len(f.errs), f.errs)
	}
	assertNoDomainEmissions(t, f)
}

// TestNormalizeSameDayEmissionIsDeterministic proves one payload normalises
// to one identical emission (ARCH-002 §1 determinism): two passes over the
// same raw record — the re-import of the same day's file at the normalise
// level — produce the identical row stream and the identical row count.
// (The *skip* of the same-day reload happens before the pass, on the
// content-hash no-op of the fetch/run path; see the no-op fetch test.)
func TestNormalizeSameDayEmissionIsDeterministic(t *testing.T) {
	firstBulk, _, res1 := runNormalize(t, epssCSV, &fakeBulkWriter{})
	secondBulk, _, res2 := runNormalize(t, epssCSV, &fakeBulkWriter{})

	if res1.Records != res2.Records || res1.Errors != res2.Errors {
		t.Errorf("results differ between passes: %+v vs %+v", res1, res2)
	}
	if !reflect.DeepEqual(firstBulk.rows, secondBulk.rows) {
		t.Errorf("row streams differ between passes:\n%+v\n%+v", firstBulk.rows, secondBulk.rows)
	}
}

// TestNormalizeMissingValuesAbsentNotZero pins ch. 8.4: a data line missing
// any of its three values is recorded as absent — the row is not loaded and
// no zero is fabricated for it. An explicit 0.00000 in the file is data and
// loads like any other value; a row of empty columns is a stray blank, not
// an error. Absence is not counted and not quarantined.
func TestNormalizeMissingValuesAbsentNotZero(t *testing.T) {
	const missingCSV = `#model_version:v2026.03.01,score_date:2026-09-09T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.97368,0.9991
CVE-2026-0002,0.00510,
CVE-2026-0003,,0.1937
CVE-2026-0004,0.00000,0.00000
,,
CVE-2026-0005,0.00057,0.1937
`
	bulk, f, res := runNormalize(t, missingCSV, &fakeBulkWriter{})

	// Only the complete rows are loaded: 0001, the explicit-zero 0004 and
	// 0005 — the blank-percentile row, the blank-score row and the empty
	// row stay absent.
	want := []application.EpssRow{
		{CveID: "CVE-2026-0001", Score: "0.97368", Percentile: "0.9991"},
		{CveID: "CVE-2026-0004", Score: "0.00000", Percentile: "0.00000"},
		{CveID: "CVE-2026-0005", Score: "0.00057", Percentile: "0.1937"},
	}
	if !reflect.DeepEqual(bulk.rows, want) {
		t.Errorf("streamed rows = %+v, want %+v (missing values absent, explicit zeros loaded)", bulk.rows, want)
	}
	if res.Records != len(want) {
		t.Errorf("NormalizeResult.Records = %d, want %d (loaded rows only)", res.Records, len(want))
	}
	// Absence is the file's own data state — neither an error nor a
	// quarantine candidate.
	if res.Errors != 0 {
		t.Errorf("NormalizeResult.Errors = %d, want 0 (absence is not an error)", res.Errors)
	}
	if len(f.errs) != 0 {
		t.Errorf("absent rows were quarantined: %+v", f.errs)
	}
}

// TestNormalizeIsolatesMalformedRows proves the isolation contract of
// present-but-invalid lines: an unparsable score, a present score outside
// [0,1], a two-column row and a row with broken quoting are each isolated
// through sink.RecordError (position "line N", a stable reason code and the
// SHA-256 of the offending line) while the healthy rows still flow.
func TestNormalizeIsolatesMalformedRows(t *testing.T) {
	const malformedCSV = `#model_version:v2026.03.01,score_date:2026-09-09T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.97368,0.9991
CVE-2026-0002,abc,0.4021
CVE-2026-0003,0.00510
CVE-2026-0004,1.50000,0.9000
CVE-2026-0005,0.00510,0.4021,"oops
CVE-2026-0006,0.00057,0.1937
`
	bulk, f, res := runNormalize(t, malformedCSV, &fakeBulkWriter{})

	if want := 2; res.Records != want { // the healthy lines 3 and 8
		t.Errorf("NormalizeResult.Records = %d, want %d", res.Records, want)
	}
	if want := 4; res.Errors != want {
		t.Errorf("NormalizeResult.Errors = %d, want %d", res.Errors, want)
	}
	if len(bulk.rows) != 2 || bulk.rows[0].CveID != "CVE-2026-0001" || bulk.rows[1].CveID != "CVE-2026-0006" {
		t.Fatalf("streamed rows = %+v, want the two healthy rows only", bulk.rows)
	}
	if len(f.errs) != 4 {
		t.Fatalf("emitted %d RecordErrors, want 4", len(f.errs))
	}

	lines := strings.Split(malformedCSV, "\n")
	// The offending raw lines, as written (1-based lines 4, 5, 6 and 7).
	wantLines := []string{lines[3], lines[4], lines[5], lines[6]}
	wantCodes := []string{reasonInvalidNumber, reasonRowCSV, reasonInvalidNumber, reasonRowCSV}
	for i, want := range wantLines {
		got := f.errs[i]
		wantPos := fmt.Sprintf("line %d", i+4)
		if got.Position != wantPos {
			t.Errorf("RecordError %d position = %q, want %q", i, got.Position, wantPos)
		}
		if !strings.HasPrefix(got.Reason, wantCodes[i]) {
			t.Errorf("RecordError %d reason = %q, want the stable code prefix %s", i, got.Reason, wantCodes[i])
		}
		if got.PayloadHash != sha256Hex([]byte(want)) {
			t.Errorf("RecordError %d PayloadHash = %s, want %s (SHA-256 of the offending line)", i, got.PayloadHash, sha256Hex([]byte(want)))
		}
	}
}

// TestNormalizeDocumentNotGzip: a payload whose first bytes are no gzip
// member is isolated whole (position "document", hashed) — a counted,
// non-fatal error, not an abort.
func TestNormalizeDocumentNotGzip(t *testing.T) {
	in := application.NormalizeInput{
		RawRecordID: "raw-epss-1",
		Payload:     []byte("this is not a gzip stream"),
		ContentHash: "fixture",
		EpssBulk:    &fakeBulkWriter{},
	}
	f := &fakeSink{}
	res, err := new(Adapter).Normalize(context.Background(), in, f)
	if err != nil {
		t.Fatalf("Normalize of a non-gzip payload: unexpected error: %v", err)
	}
	if res.Errors != 1 || res.Records != 0 {
		t.Fatalf("result = %+v, want 1 error and no records", res)
	}
	if len(f.errs) != 1 {
		t.Fatalf("emitted %d RecordErrors, want 1", len(f.errs))
	}
	e := f.errs[0]
	if e.Position != "document" || !strings.HasPrefix(e.Reason, reasonDocumentGzip) {
		t.Errorf("RecordError = %+v, want the document position and the gzip code", e)
	}
	if e.PayloadHash != sha256Hex([]byte("this is not a gzip stream")) {
		t.Errorf("PayloadHash = %s, want the SHA-256 of the whole payload", e.PayloadHash)
	}
}

// TestNormalizeRequiresBulkWriter: the EPSS bulk path is the port's
// documented specialisation — the adapter requires NormalizeInput.EpssBulk
// and errors loudly when the source-run wiring has not handed it over
// (nothing may be loaded silently). The other sources never read the field.
func TestNormalizeRequiresBulkWriter(t *testing.T) {
	in := application.NormalizeInput{
		RawRecordID: "raw-epss-1",
		Payload:     gzipBytes(t, epssCSV),
		ContentHash: "fixture",
		// EpssBulk is nil — the unwired path.
	}
	f := &fakeSink{}
	res, err := new(Adapter).Normalize(context.Background(), in, f)
	if err == nil || !strings.Contains(err.Error(), "EpssBulk") {
		t.Fatalf("Normalize without the bulk writer error = %v, want an EpssBulk wiring error", err)
	}
	if res.Records != 0 || res.Errors != 0 {
		t.Errorf("result = %+v, want no rows and no errors on the wiring error", res)
	}
}

// TestNormalizeBulkWriteFailureAborts: a failing persistence write is an
// infrastructure failure — the pass returns the error and nothing of it may
// be committed as a load (the run transaction rolls back, the previous
// day's set stays intact).
func TestNormalizeBulkWriteFailureAborts(t *testing.T) {
	bulk := &fakeBulkWriter{failAfter: 2} // the second row fails
	in := application.NormalizeInput{
		RawRecordID: "raw-epss-1",
		Payload:     gzipBytes(t, epssCSV),
		ContentHash: "fixture",
		EpssBulk:    bulk,
	}
	f := &fakeSink{}
	_, err := new(Adapter).Normalize(context.Background(), in, f)
	if err == nil || !strings.Contains(err.Error(), "bulk write failed") {
		t.Fatalf("Normalize with a failing writer error = %v, want the writer's error", err)
	}
	if len(f.errs) != 0 {
		t.Errorf("a failing write isolated %d records, want 0 (it is an infrastructure error, not a record error)", len(f.errs))
	}
}

// TestNormalizeScientificNotationPercentiles: the real daily file renders
// very small percentiles in scientific notation ("7e-05") — a literal the
// numeric column accepts and the normaliser must load as-is, not isolate
// (the exponent-aware conversion mirrors the COPY path's).
func TestNormalizeScientificNotationPercentiles(t *testing.T) {
	const sciCSV = `#model_version:v2026.03.01,score_date:2026-09-09T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.0006,7e-05
CVE-2026-0002,0.00054,2e-05
CVE-2026-0003,9.9e-1,0.9999
`
	bulk, f, res := runNormalize(t, sciCSV, &fakeBulkWriter{})

	if res.Errors != 0 || res.Records != 3 {
		t.Fatalf("result = %+v, want 3 records and 0 errors", res)
	}
	want := []application.EpssRow{
		{CveID: "CVE-2026-0001", Score: "0.0006", Percentile: "7e-05"},
		{CveID: "CVE-2026-0002", Score: "0.00054", Percentile: "2e-05"},
		{CveID: "CVE-2026-0003", Score: "9.9e-1", Percentile: "0.9999"},
	}
	if !reflect.DeepEqual(bulk.rows, want) {
		t.Errorf("streamed rows = %+v, want %+v (literals travel unchanged)", bulk.rows, want)
	}
	if len(f.errs) != 0 {
		t.Errorf("scientific-notation rows were isolated: %+v", f.errs)
	}
}

// TestNormalizeMultiMemberGzip: the real daily files are concatenations of
// gzip members (the FIRST publisher gzips the CSV in chunks). Go's
// gzip.Reader consumes multi-member streams transparently, so a split
// fixture decompresses and streams exactly like a single-member one.
func TestNormalizeMultiMemberGzip(t *testing.T) {
	const head = `#model_version:v2026.03.01,score_date:2026-09-09T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.97368,0.9991
`
	const tail = `CVE-2026-0002,0.00510,0.4021
CVE-2026-0003,0.00057,0.1937
`
	var payload bytes.Buffer
	for _, part := range []string{head, tail} {
		zw := gzip.NewWriter(&payload)
		if _, err := zw.Write([]byte(part)); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	}

	bulk := &fakeBulkWriter{}
	in := application.NormalizeInput{
		RawRecordID: "raw-epss-1",
		Payload:     payload.Bytes(),
		ContentHash: "fixture",
		EpssBulk:    bulk,
	}
	f := &fakeSink{}
	res, err := new(Adapter).Normalize(context.Background(), in, f)
	if err != nil {
		t.Fatalf("Normalize of a multi-member gzip: unexpected error: %v", err)
	}
	if res.Records != 3 || res.Errors != 0 {
		t.Fatalf("result = %+v, want 3 records and 0 errors", res)
	}
	if len(bulk.rows) != 3 || bulk.rows[2].CveID != "CVE-2026-0003" {
		t.Errorf("streamed rows = %+v, want all rows of both members in order", bulk.rows)
	}
}
