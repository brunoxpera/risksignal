package application_test

// Unit tests of the I2 source run use cases (DEV-030 / WP-2.04, ARCH-002
// §1, §5, §6) with in-memory fakes: FetchSource (open run -> fetch -> store
// raw -> complete with cursor on success, enqueue the source.normalize job
// in the same transaction), RunSource (the full fetch+normalise cycle in
// one run), NormalizeSource (the normalise half with per-record isolation
// that never aborts the run) — and the two fault seams of ARCH-002 §6: a
// failing sink write and a failing outbox append both roll the run back
// with nothing partially committed, and the cursor advances only after the
// commit of a successful run (ch. 6.1).

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// runSource is a controllable SourcePort for the run use-case tests: the
// fetch output/error are fixed by the test, the normalise pass is a script
// that streams into the sink the test receives.
type runSource struct {
	typ       application.SourceType
	plan      application.SourcePlan
	fetchOut  application.FetchOutput
	fetchErr  error
	normalize func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error)

	lastFetchIn application.FetchInput
	lastNormIn  application.NormalizeInput
}

func (s *runSource) Type() application.SourceType { return s.typ }
func (s *runSource) Plan() application.SourcePlan { return s.plan }
func (s *runSource) NormalizerVersion() string    { return "test-normalizer-v1" }
func (s *runSource) Fetch(ctx context.Context, in application.FetchInput) (application.FetchOutput, error) {
	s.lastFetchIn = in
	return s.fetchOut, s.fetchErr
}
func (s *runSource) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	s.lastNormIn = in
	if s.normalize == nil {
		return application.NormalizeResult{}, nil
	}
	return s.normalize(ctx, in, sink)
}

// compile-time check: the fake must satisfy the exact port shape.
var _ application.SourcePort = (*runSource)(nil)

// emitVuln streams one normalised vulnerability into the sink the way the
// WP-2.05+ adapters will: plain structs carrying the natural key and the
// statement fields, never database ids (the persistence sink attributes).
func emitVuln(ctx context.Context, sink application.NormalizeSink, cveID, summary string) error {
	return sink.Vulnerability(ctx, domain.Vulnerability{CVEID: cveID, Summary: summary})
}

// emitEvidence streams one immutable source statement whose value carries
// the cve_id — the attribution key the persistence sink resolves.
func emitEvidence(ctx context.Context, sink application.NormalizeSink, cveID string, typ domain.EvidenceType) error {
	return sink.Evidence(ctx, domain.Evidence{
		Type:  typ,
		Value: map[string]any{"cve_id": cveID},
	})
}

// decodeJSON parses a jsonb round-trip value for semantic comparison.
func decodeJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode json %q: %v", b, err)
	}
	return v
}

// nvdSource seeds an incremental NVD-style source with a stored cursor and
// returns its adapter fake, pre-wired to fetch one windowed slice.
func nvdSource(h *harness, t *testing.T) *runSource {
	t.Helper()
	cursor := json.RawMessage(`{"last_modified":"2026-09-09T07:00:00Z"}`)
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID:     "src-nvd",
		Type:   application.SourceTypeNVD,
		Config: map[string]any{"overlap": 2.0, "api_key_ref": "env:RISKSIGNAL_NVD_API_KEY"},
		Cursor: cursor,
	})
	return &runSource{
		typ: application.SourceTypeNVD,
		plan: application.SourcePlan{
			Schedule:   "@hourly",
			Kind:       application.SourceKindIncremental,
			CursorKind: application.CursorKindLastModified,
		},
		fetchOut: application.FetchOutput{
			ExternalID:  "nvd:2026-09-09T05:00:00Z:2026-09-09T09:30:00Z:page-0",
			Payload:     []byte(`{"vulnerabilities":[{"id":"CVE-2026-1001"}]}`),
			ContentHash: "fetch-hash-1",
			FetchedAt:   fixedNow,
			Cursor:      json.RawMessage(`{"last_modified":"2026-09-09T09:30:00Z"}`),
			Meta: application.FetchMeta{
				Status:      200,
				ContentType: "application/json",
			},
		},
	}
}

// TestFetchSourceHappyPath is the required FetchSource behaviour: open the
// run from the source cursor, fetch one slice (window = cursor minus the
// configured overlap, to = the injected clock), store the unchanged raw
// record, complete the run succeeded with the advanced cursor and enqueue
// the source.normalize job — all committed atomically.
func TestFetchSourceHappyPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := nvdSource(h, t)

	res, err := h.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: "src-nvd", Adapter: src})
	if err != nil {
		t.Fatalf("FetchSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.RawRecordID == "" {
		t.Fatalf("result = %+v, want succeeded with a stored raw record", res)
	}

	// The adapter received the resolved descriptor and the bounded window:
	// From = cursor (07:00Z) minus the 2 h overlap, To = the injected clock.
	if src.lastFetchIn.Source.ID != "src-nvd" || src.lastFetchIn.Source.Cursor == nil {
		t.Fatalf("fetch input source = %+v, want the resolved descriptor with its cursor", src.lastFetchIn.Source)
	}
	if !src.lastFetchIn.Window.From.Equal(time.Date(2026, 9, 9, 5, 0, 0, 0, time.UTC)) {
		t.Fatalf("window From = %v, want 05:00Z (07:00Z cursor minus 2 h overlap)", src.lastFetchIn.Window.From)
	}
	if !src.lastFetchIn.Window.To.Equal(fixedNow) {
		t.Fatalf("window To = %v, want the injected clock %v", src.lastFetchIn.Window.To, fixedNow)
	}
	if src.lastFetchIn.APIKeyRef != "env:RISKSIGNAL_NVD_API_KEY" {
		t.Fatalf("API key reference = %q, want the config reference (never the literal)", src.lastFetchIn.APIKeyRef)
	}

	// One committed run: opened from cursor_before, closed succeeded with
	// the advanced cursor_after and records 1.
	if len(h.db.sourceRuns) != 1 {
		t.Fatalf("runs = %d, want 1", len(h.db.sourceRuns))
	}
	run := h.db.sourceRuns[0]
	if run.status != "succeeded" {
		t.Fatalf("run status = %q, want succeeded", run.status)
	}
	if string(run.cursorBefore) != `{"last_modified":"2026-09-09T07:00:00Z"}` {
		t.Fatalf("cursor_before = %s, want the source cursor the run opened from", run.cursorBefore)
	}
	if string(run.cursorAfter) != string(src.fetchOut.Cursor) {
		t.Fatalf("cursor_after = %s, want the fetch cursor %s (advanced only on success)", run.cursorAfter, src.fetchOut.Cursor)
	}
	if run.counters.Records != 1 || run.counters.Normalized != 0 {
		t.Fatalf("counters = %+v, want records 1", run.counters)
	}

	// The unchanged raw record was stored with its self-describing encoding
	// (content type application/json -> 'json') and the normalize job was
	// enqueued on the same commit.
	if len(h.db.rawRecords) != 1 {
		t.Fatalf("raw records = %d, want 1", len(h.db.rawRecords))
	}
	raw := h.db.rawRecords[0]
	if raw.id != res.RawRecordID || raw.contentEncoding != "json" || string(raw.payload) != string(src.fetchOut.Payload) {
		t.Fatalf("raw record = %+v, want the unchanged payload stamped json", raw)
	}
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox events = %d, want the source.normalize job", len(h.db.outboxEvents))
	}
	job := h.db.outboxEvents[0]
	if job.Type != application.EventTypeSourceNormalize {
		t.Fatalf("job type = %q, want %q", job.Type, application.EventTypeSourceNormalize)
	}
	if job.DedupeKey != "source.normalize:"+raw.id+":test-normalizer-v1" {
		t.Fatalf("job dedupe key = %q, want source.normalize:<raw_record_id>:<normalizer_version>", job.DedupeKey)
	}
}

// TestFetchSourceMalformedCursorIsValidation tests the ch. 5.2 error
// semantics of the fetch path: an operator-data mistake (a malformed stored
// cursor) is a validation error and opens no run.
func TestFetchSourceMalformedCursorIsValidation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID:     "src-bad",
		Type:   application.SourceTypeNVD,
		Cursor: json.RawMessage(`{"last_modified":"not-a-time"}`),
	})
	src := &runSource{
		typ: application.SourceTypeNVD,
		plan: application.SourcePlan{
			Kind: application.SourceKindIncremental, CursorKind: application.CursorKindLastModified,
		},
	}
	_, err := h.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: "src-bad", Adapter: src})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error = %v, want a validation error for the malformed cursor", err)
	}
	if len(h.db.sourceRuns) != 0 {
		t.Fatalf("runs = %d, want 0 — validation opens no run", len(h.db.sourceRuns))
	}
}

// TestFetchSourceRateLimitedIsNotAnError is the required rate-limit
// semantics (ARCH-002 §2.1, ch. 14.2): a 429/503 fetch is recorded on the
// run as rate-limited — never as a source technical error — the run closes
// failed, the cursor does not advance and nothing is stored.
func TestFetchSourceRateLimitedIsNotAnError(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := nvdSource(h, t)
	src.fetchOut = application.FetchOutput{
		Meta: application.FetchMeta{RateLimited: true, RetryAfter: 60},
	}

	res, err := h.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: "src-nvd", Adapter: src})
	if err != nil {
		t.Fatalf("rate-limited fetch must not error: %v", err)
	}
	if !res.Meta.RateLimited || res.Status != application.SourceRunStatusFailed {
		t.Fatalf("result = %+v, want a failed run surfaced with Meta.RateLimited", res)
	}
	run := h.db.sourceRuns[0]
	if run.status != "failed" || run.errText != "fetch.rate_limited" || run.cursorAfter != nil {
		t.Fatalf("run = status %q error %q cursor %s, want failed with the rate-limit code and no cursor", run.status, run.errText, run.cursorAfter)
	}
	if len(h.db.rawRecords) != 0 || len(h.db.outboxEvents) != 0 {
		t.Fatalf("raw records/outbox = %d/%d, want 0 — nothing stored on a rate-limited fetch", len(h.db.rawRecords), len(h.db.outboxEvents))
	}
}

// TestFetchSourceInfraFailureClosesRunFailed tests the fetch fault path: an
// infrastructure failure closes the run failed with the error text and the
// cursor stays where it was (the next run re-fetches the same window).
func TestFetchSourceInfraFailureClosesRunFailed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := nvdSource(h, t)
	src.fetchErr = errors.New("dial tcp: connection refused")

	_, err := h.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: "src-nvd", Adapter: src})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error = %v, want an infrastructure error", err)
	}
	run := h.db.sourceRuns[0]
	if run.status != "failed" || !strings.Contains(run.errText, "dial tcp") || run.cursorAfter != nil {
		t.Fatalf("run = status %q error %q cursor %s, want failed and no cursor", run.status, run.errText, run.cursorAfter)
	}
	if len(h.db.rawRecords) != 0 {
		t.Fatalf("raw records = %d, want 0", len(h.db.rawRecords))
	}
}

// TestRunSourceHappyPathIsIdempotent is the required RunSource test: the
// full cycle (fetch + normalise in one run) commits the raw record, the
// normalised domain objects and the advanced cursor, and a second identical
// run — the twofold reference import of ARCH-002 §6 — produces no
// duplicates at any level and reports the same counters.
func TestRunSourceHappyPathIsIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := nvdSource(h, t)
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if err := emitVuln(ctx, sink, "CVE-2026-1001", "summary one"); err != nil {
			return application.NormalizeResult{}, err
		}
		if err := emitEvidence(ctx, sink, "CVE-2026-1001", domain.EvidenceTypeNVDStatement); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 2}, nil
	}

	run := func() application.RunSourceResult {
		t.Helper()
		res, err := h.svc.RunSource(ctx, application.RunSourceInput{SourceID: "src-nvd", Adapter: src})
		if err != nil {
			t.Fatalf("RunSource: %v", err)
		}
		return res
	}
	res1 := run()
	if res1.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("run status = %s, want succeeded", res1.Status)
	}
	if res1.Counters.Records != 1 || res1.Counters.Normalized != 2 || res1.Counters.Errors != 0 {
		t.Fatalf("counters = %+v, want records 1 normalized 2 errors 0", res1.Counters)
	}
	if !reflect.DeepEqual(decodeJSON(t, res1.CursorAfter), decodeJSON(t, []byte(`{"last_modified":"2026-09-09T09:30:00Z"}`))) {
		t.Fatalf("cursor_after = %s, want the fetch cursor committed", res1.CursorAfter)
	}
	if src.lastNormIn.RawRecordID != res1.RawRecordID || string(src.lastNormIn.Payload) != string(src.fetchOut.Payload) {
		t.Fatalf("normalise input = %+v, want the stored raw record of this run", src.lastNormIn)
	}

	// Second identical run: no duplicates anywhere, same counters (the
	// natural-key idempotency of ARCH-002 §6 exit criterion 1).
	res2 := run()
	if !reflect.DeepEqual(res2.Counters, res1.Counters) {
		t.Fatalf("second run counters = %+v, want identical to the first %+v", res2.Counters, res1.Counters)
	}
	if res2.RawRecordID != res1.RawRecordID {
		t.Fatalf("second raw record id = %s, want the existing record %s (ON CONFLICT DO NOTHING)", res2.RawRecordID, res1.RawRecordID)
	}
	if len(h.db.rawRecords) != 1 || len(h.db.vulns) != 1 || len(h.db.evidenceRows) != 1 {
		t.Fatalf("after two runs: raw/vulns/evidences = %d/%d/%d, want 1/1/1 (no duplicates)", len(h.db.rawRecords), len(h.db.vulns), len(h.db.evidenceRows))
	}
	if len(h.db.sourceRuns) != 2 {
		t.Fatalf("runs = %d, want 2", len(h.db.sourceRuns))
	}
}

// TestRunSourceFailingSinkRollsBackRunAndCursor is the ARCH-002 §6 fault
// seam: a sink write failing mid-pass rolls the run back with nothing
// partially committed — no raw record, no normalised objects — and the
// cursor is NOT advanced (the next run re-fetches the same window).
func TestRunSourceFailingSinkRollsBackRunAndCursor(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := nvdSource(h, t)
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if err := emitVuln(ctx, sink, "CVE-2026-1001", "summary one"); err != nil {
			return application.NormalizeResult{}, err
		}
		// The second write fails mid-stream (the injected sink fault).
		if err := emitEvidence(ctx, sink, "CVE-2026-1001", domain.EvidenceTypeNVDStatement); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 2}, nil
	}
	h.vulns.failEvidence = errors.New("sink: evidence write failed")

	_, err := h.svc.RunSource(ctx, application.RunSourceInput{SourceID: "src-nvd", Adapter: src})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error = %v, want an infrastructure error from the failing sink", err)
	}

	// The run was closed failed — without a cursor. Nothing of the pass
	// committed: no raw record, no vulnerability, no evidence.
	run := h.db.sourceRuns[0]
	if run.status != "failed" || !strings.Contains(run.errText, "sink: evidence write failed") {
		t.Fatalf("run = status %q error %q, want failed with the sink error", run.status, run.errText)
	}
	if run.cursorAfter != nil || string(run.cursorBefore) == "" {
		t.Fatalf("run cursor after = %s before = %s, want no cursor_after (cursor advances only on commit)", run.cursorAfter, run.cursorBefore)
	}
	if len(h.db.rawRecords) != 0 || len(h.db.vulns) != 0 || len(h.db.evidenceRows) != 0 {
		t.Fatalf("raw/vulns/evidences = %d/%d/%d, want 0 — nothing partially committed", len(h.db.rawRecords), len(h.db.vulns), len(h.db.evidenceRows))
	}
}

// TestFetchSourceFailingOutboxAppendRollsBackCommit is the ARCH-002 §6
// outbox fault seam: the source.normalize job is appended inside the fetch
// run's terminal commit — a failing append rolls back the run completion,
// the stored raw record and the cursor together.
func TestFetchSourceFailingOutboxAppendRollsBackCommit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	src := nvdSource(h, t)
	h.outbox.failpoint = errors.New("outbox: append failed")

	_, err := h.svc.FetchSource(ctx, application.FetchSourceInput{SourceID: "src-nvd", Adapter: src})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error = %v, want an infrastructure error from the failing outbox append", err)
	}
	run := h.db.sourceRuns[0]
	if run.status != "failed" || !strings.Contains(run.errText, "outbox: append failed") {
		t.Fatalf("run = status %q error %q, want failed with the outbox error", run.status, run.errText)
	}
	if run.cursorAfter != nil {
		t.Fatalf("cursor_after = %s, want nil — the failing outbox append rolled the cursor back", run.cursorAfter)
	}
	if len(h.db.rawRecords) != 0 || len(h.db.outboxEvents) != 0 {
		t.Fatalf("raw records/outbox = %d/%d, want 0 — the terminal commit rolled back entirely", len(h.db.rawRecords), len(h.db.outboxEvents))
	}
}

// TestNormalizeSourceIsolatesRecordErrorsWithoutAborting is the required
// per-record isolation behaviour (ARCH-002 §1, §4; ch. 8.1 step 5): a
// record that fails to parse is isolated into quarantine — positioned,
// attributed and re-addressable — and the run still succeeds with errors >
// 0 counted in the counters.
func TestNormalizeSourceIsolatesRecordErrorsWithoutAborting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// A committed raw record the normalise half re-processes.
	h.db.rawRecords = append(h.db.rawRecords, storedRawRecord{
		id: "raw-1", sourceID: "src-kev", externalID: "kev-2026-09-09",
		contentHash: "kev-hash", contentEncoding: "json",
		payload: []byte(`[{"cveID":"CVE-2026-2001"},{"cveID":""}]`), fetchedAt: fixedNow,
	})
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID: "src-kev", Type: application.SourceTypeKEV,
	})
	src := &runSource{typ: application.SourceTypeKEV}
	src.normalize = func(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
		if err := emitVuln(ctx, sink, "CVE-2026-2001", "kev skeleton"); err != nil {
			return application.NormalizeResult{}, err
		}
		if err := emitEvidence(ctx, sink, "CVE-2026-2001", domain.EvidenceTypeKEV); err != nil {
			return application.NormalizeResult{}, err
		}
		// The malformed second record is isolated, never fatal.
		if err := sink.RecordError(ctx, application.RecordError{
			Position:    "records/1",
			Reason:      "parse.invalid_cve_id: CVE id is empty",
			PayloadHash: "hash-of-offending-slice",
		}); err != nil {
			return application.NormalizeResult{}, err
		}
		return application.NormalizeResult{Records: 2, Errors: 1}, nil
	}

	res, err := h.svc.NormalizeSource(ctx, application.NormalizeSourceInput{RawRecordID: "raw-1", Adapter: src})
	if err != nil {
		t.Fatalf("NormalizeSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("status = %s, want succeeded — isolated errors never abort the run", res.Status)
	}
	if res.Counters.Records != 1 || res.Counters.Normalized != 2 || res.Counters.Errors != 1 || res.Counters.Quarantined != 1 {
		t.Fatalf("counters = %+v, want records 1 normalized 2 errors 1 quarantined 1", res.Counters)
	}

	// The isolation row is committed with the full attribution: source, run
	// and raw record of the pass.
	if len(h.db.quarantine) != 1 {
		t.Fatalf("quarantine rows = %d, want 1", len(h.db.quarantine))
	}
	q := h.db.quarantine[0]
	if q.SourceID != "src-kev" || q.SourceRunID != res.RunID || q.RawRecordID != "raw-1" {
		t.Fatalf("quarantine attribution = source %s run %s raw %s, want src-kev/%s/raw-1", q.SourceID, q.SourceRunID, q.RawRecordID, res.RunID)
	}
	if q.Status != domain.QuarantineStatusNew || q.Position != "records/1" || q.PayloadHash != "hash-of-offending-slice" {
		t.Fatalf("quarantine row = %+v, want a new, positioned, re-addressable isolation", q)
	}
	if len(h.db.vulns) != 1 || len(h.db.evidenceRows) != 1 {
		t.Fatalf("vulns/evidences = %d/%d, want the good record persisted alongside the isolation", len(h.db.vulns), len(h.db.evidenceRows))
	}
}
