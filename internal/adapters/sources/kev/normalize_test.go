package kev

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// normalizeInput builds the NormalizeInput of a pass over payload with the
// given previous full-set (raw record id and content hash are opaque to
// the normaliser).
func normalizeInput(payload string, previous ...string) application.NormalizeInput {
	return application.NormalizeInput{
		RawRecordID:     "raw-kev-1",
		Payload:         []byte(payload),
		ContentHash:     "fixture",
		PreviousKEVCVEs: previous,
	}
}

// runNormalize runs one pass over payload and fails the test on an
// unexpected error.
func runNormalize(t *testing.T, in application.NormalizeInput) (*fakeNormalizeSink, application.NormalizeResult) {
	t.Helper()
	f := &fakeNormalizeSink{}
	res, err := new(Adapter).Normalize(context.Background(), in, f)
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}
	return f, res
}

// fakeNormalizeSink records every emission of a pass in arrival order.
type fakeNormalizeSink struct {
	events []string
	vulns  []domain.Vulnerability
	evids  []domain.Evidence
	errs   []application.RecordError
}

func (f *fakeNormalizeSink) Vulnerability(_ context.Context, v domain.Vulnerability) error {
	f.vulns = append(f.vulns, v)
	f.events = append(f.events, "vulnerability:"+v.CVEID)
	return nil
}

func (f *fakeNormalizeSink) Evidence(_ context.Context, e domain.Evidence) error {
	f.evids = append(f.evids, e)
	f.events = append(f.events, "evidence:"+string(e.Type)+":"+cveIDOfEvidence(e))
	return nil
}

func (f *fakeNormalizeSink) RecordError(_ context.Context, e application.RecordError) error {
	f.errs = append(f.errs, e)
	f.events = append(f.events, "error:"+e.Reason)
	return nil
}

// cveIDOfEvidence reads the cve_id the canonical value carries — the same
// probe the persistence sink uses to attribute an evidence to its
// vulnerability.
func cveIDOfEvidence(e domain.Evidence) string {
	b, err := json.Marshal(e.Value)
	if err != nil {
		return "<unmarshalable>"
	}
	var probe struct {
		CveID string `json:"cve_id"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return "<no-cve_id>"
	}
	return probe.CveID
}

// canonicalValue renders one evidence value in its canonical JSON form —
// what the value hash is computed over (UQ (raw_record_id, type,
// value_hash)).
func canonicalValue(e domain.Evidence) string {
	b, err := json.Marshal(e.Value)
	if err != nil {
		return "<unmarshalable>"
	}
	return string(b)
}

// TestNormalizeEmitsSkeletonAndKEVEvidence drives one pass over a catalog
// of three entries and asserts the full emission: per entry one skeleton
// vulnerability (cve_id, summary = shortDescription, no descriptive
// fields) followed by its kev evidence whose canonical value carries the
// full ARCH-002 §2.2 field set — dates normalised to YYYY-MM-DD, an empty
// dueDate recorded as absent.
func TestNormalizeEmitsSkeletonAndKEVEvidence(t *testing.T) {
	payload := catalogDoc("2026-09-09T04:00:00.000Z", "2026.09.09", entryA, entryB, entryC)
	f, res := runNormalize(t, normalizeInput(payload))

	if res.Errors != 0 {
		t.Errorf("NormalizeResult.Errors = %d, want 0", res.Errors)
	}
	if want := 3 + 3; res.Records != want { // 3 skeletons + 3 kev evidences
		t.Errorf("NormalizeResult.Records = %d, want %d", res.Records, want)
	}

	// Emission order: each entry's skeleton precedes its evidence.
	wantEvents := []string{
		"vulnerability:CVE-2026-0001",
		"evidence:kev:CVE-2026-0001",
		"vulnerability:CVE-2026-0002",
		"evidence:kev:CVE-2026-0002",
		"vulnerability:CVE-2026-0003",
		"evidence:kev:CVE-2026-0003",
	}
	assertStrings(t, "emission order", f.events, wantEvents)

	if len(f.vulns) != 3 {
		t.Fatalf("emitted %d vulnerabilities, want 3", len(f.vulns))
	}
	wantSummaries := map[string]string{
		"CVE-2026-0001": "Stack overflow in the Acme Widget Parser allows remote code execution.",
		"CVE-2026-0002": "Use-after-free in the Acme Widget Parser leads to code execution.",
		"CVE-2026-0003": "Command injection in the Beta Gateway allows remote takeover.",
	}
	for _, v := range f.vulns {
		if v.Summary != wantSummaries[v.CVEID] {
			t.Errorf("skeleton %s summary = %q, want the shortDescription", v.CVEID, v.Summary)
		}
		// A skeleton carries no descriptive fields — the persistence
		// upsert never lets it clobber an existing full NVD row.
		if v.Description != "" || v.CVSS != nil || v.References != nil || v.CPECfg != nil {
			t.Errorf("skeleton %s = %+v, want no descriptive fields", v.CVEID, v)
		}
	}

	// The kev evidences: canonical values pinned byte-for-byte (fixed
	// field order, full field set, superset of the I1b {cve_id,
	// known_exploited} shape).
	if len(f.evids) != 3 {
		t.Fatalf("emitted %d evidences, want 3", len(f.evids))
	}
	golden := []string{
		`{"cve_id":"CVE-2026-0001","vendor":"Acme Corporation","product":"Widget Parser","vulnerability_name":"Acme Widget Parser Stack Overflow","date_added":"2026-08-01","known_exploited":true,"required_action":"Apply vendor-supplied mitigations or discontinue use.","due_date":"2026-10-01","known_ransomware":true}`,
		`{"cve_id":"CVE-2026-0002","vendor":"Acme Corporation","product":"Widget Parser","vulnerability_name":"Acme Widget Parser Use-After-Free","date_added":"2026-08-15","known_exploited":true,"required_action":"Apply vendor-supplied mitigations.","due_date":"","known_ransomware":false}`,
		`{"cve_id":"CVE-2026-0003","vendor":"Beta Systems","product":"Gateway","vulnerability_name":"Beta Gateway Command Injection","date_added":"2026-09-01","known_exploited":true,"required_action":"Apply the vendor update.","due_date":"2026-11-01","known_ransomware":false}`,
	}
	for i, e := range f.evids {
		if e.Type != domain.EvidenceTypeKEV {
			t.Errorf("evidence %d type = %q, want kev", i, e.Type)
		}
		if got := canonicalValue(e); got != golden[i] {
			t.Errorf("evidence %d value = %s, want the canonical full field set %s", i, got, golden[i])
		}
	}
}

// TestNormalizeHistorisesRemovals is the changed-catalog path (ch. 8.3,
// ARCH-002 §2.2): the new catalog drops CVE-2026-0002 and CVE-2026-0003;
// the previous set arrives through NormalizeInput.PreviousKEVCVEs. Every
// removed CVE gets its skeleton re-upserted (the sink attributes an
// evidence to a vulnerability this pass upserted) and a kev_removed
// evidence — a new evidence version, never an in-place edit (ch. 6.1).
func TestNormalizeHistorisesRemovals(t *testing.T) {
	// The new catalog only carries CVE-2026-0001; the previous set lists
	// the dropped CVEs in arbitrary order plus a duplicate, an empty id
	// and a CVE that is still present.
	payload := catalogDoc("2026-09-10T04:00:00.000Z", "2026.09.10", entryA)
	f, res := runNormalize(t, normalizeInput(payload,
		"CVE-2026-0003", "CVE-2026-0001", "", "CVE-2026-0002", "CVE-2026-0003"))

	if res.Errors != 0 {
		t.Errorf("NormalizeResult.Errors = %d, want 0", res.Errors)
	}
	if want := 2 + 4; res.Records != want { // 1 entry (skeleton + kev) + 2 removals (skeleton + kev_removed each)
		t.Errorf("NormalizeResult.Records = %d, want %d", res.Records, want)
	}

	wantEvents := []string{
		"vulnerability:CVE-2026-0001",
		"evidence:kev:CVE-2026-0001",
		// Removals follow the entries, sorted, each skeleton before its
		// kev_removed evidence.
		"vulnerability:CVE-2026-0002",
		"evidence:kev_removed:CVE-2026-0002",
		"vulnerability:CVE-2026-0003",
		"evidence:kev_removed:CVE-2026-0003",
	}
	assertStrings(t, "emission order", f.events, wantEvents)

	if len(f.vulns) != 3 {
		t.Fatalf("emitted %d vulnerabilities, want 3", len(f.vulns))
	}
	// The removal skeletons carry no summary — the new catalog holds no
	// statement for a removed CVE.
	for _, v := range f.vulns {
		if v.CVEID == "CVE-2026-0001" {
			continue
		}
		if v.Summary != "" {
			t.Errorf("removal skeleton %s summary = %q, want empty", v.CVEID, v.Summary)
		}
	}

	if len(f.evids) != 3 {
		t.Fatalf("emitted %d evidences, want 3", len(f.evids))
	}
	for i, e := range f.evids {
		if i == 0 {
			if e.Type != domain.EvidenceTypeKEV {
				t.Errorf("evidence 0 type = %q, want kev", e.Type)
			}
			continue
		}
		if e.Type != domain.EvidenceTypeKEVRemoved {
			t.Errorf("evidence %d type = %q, want kev_removed", i, e.Type)
		}
		// #nosec G602 — the length check above pins len(f.evids) == 3, so i
		// ranges 1..2 here and the index i-1 stays inside the two-element
		// literal slice.
		wantCVE := []string{"CVE-2026-0002", "CVE-2026-0003"}[i-1]
		if got := canonicalValue(e); got != `{"cve_id":"`+wantCVE+`"}` {
			t.Errorf("evidence %d value = %s, want the removed CVE %s", i, got, wantCVE)
		}
	}
}

// TestNormalizeNoPreviousSetEmitsNoRemovals: the first import carries no
// PreviousKEVCVEs — nothing to diff, no kev_removed evidence.
func TestNormalizeNoPreviousSetEmitsNoRemovals(t *testing.T) {
	payload := catalogDoc("2026-09-09T04:00:00.000Z", "2026.09.09", entryA)
	f, res := runNormalize(t, normalizeInput(payload))

	if res.Records != 2 || res.Errors != 0 {
		t.Fatalf("result = %+v, want 2 records, 0 errors", res)
	}
	for _, e := range f.evids {
		if e.Type == domain.EvidenceTypeKEVRemoved {
			t.Errorf("first import emitted a kev_removed evidence %+v", e)
		}
	}
}

// TestNormalizeDeterministicEmission proves that one payload normalises to
// one canonical emission: two passes over the same fixture and the same
// previous set produce the identical event stream and identical value
// hashes (the input of the UQ (raw_record_id, type, value_hash) dedupe) —
// pinned to golden canonical values, so any change to the shapes or the
// field order fails here.
func TestNormalizeDeterministicEmission(t *testing.T) {
	payload := catalogDoc("2026-09-09T04:00:00.000Z", "2026.09.09", entryA, entryB, entryC)
	in := normalizeInput(payload, "CVE-2026-0002", "CVE-2026-0004", "CVE-2026-0002", "CVE-2026-0005", "")

	first, res1 := runNormalize(t, in)
	second, res2 := runNormalize(t, in)

	if res1.Records != res2.Records || res1.Errors != res2.Errors {
		t.Errorf("results differ between passes: %+v vs %+v", res1, res2)
	}
	if len(first.events) != len(second.events) || len(first.evids) != len(second.evids) {
		t.Fatalf("emission sizes differ between passes")
	}
	for i := range first.events {
		if first.events[i] != second.events[i] {
			t.Fatalf("event %d differs between passes: %q vs %q", i, first.events[i], second.events[i])
		}
	}

	// The 3 entries' kev evidences plus the 2 removals' kev_removed
	// evidences, in emission order, pinned to their canonical values.
	golden := []string{
		`{"cve_id":"CVE-2026-0001","vendor":"Acme Corporation","product":"Widget Parser","vulnerability_name":"Acme Widget Parser Stack Overflow","date_added":"2026-08-01","known_exploited":true,"required_action":"Apply vendor-supplied mitigations or discontinue use.","due_date":"2026-10-01","known_ransomware":true}`,
		`{"cve_id":"CVE-2026-0002","vendor":"Acme Corporation","product":"Widget Parser","vulnerability_name":"Acme Widget Parser Use-After-Free","date_added":"2026-08-15","known_exploited":true,"required_action":"Apply vendor-supplied mitigations.","due_date":"","known_ransomware":false}`,
		`{"cve_id":"CVE-2026-0003","vendor":"Beta Systems","product":"Gateway","vulnerability_name":"Beta Gateway Command Injection","date_added":"2026-09-01","known_exploited":true,"required_action":"Apply the vendor update.","due_date":"2026-11-01","known_ransomware":false}`,
		`{"cve_id":"CVE-2026-0004"}`,
		`{"cve_id":"CVE-2026-0005"}`,
	}
	seen := make(map[string]bool, len(first.evids))
	for i, e := range first.evids {
		got := canonicalValue(e)
		if got != golden[i] {
			t.Errorf("evidence %d (%s) value = %s, want %s", i, e.Type, got, golden[i])
		}
		// No duplicate emission at the normalise level — the raw material
		// of the (raw_record_id, type, value_hash) dedupe.
		if seen[string(e.Type)+":"+got] {
			t.Errorf("evidence %d duplicates an earlier emission (type %s, value %s)", i, e.Type, got)
		}
		seen[string(e.Type)+":"+got] = true
		if second.evids[i].Type != e.Type || canonicalValue(second.evids[i]) != got {
			t.Errorf("evidence %d is not stable across passes", i)
		}
	}
}

// TestNormalizeIsolatesMalformedRecords proves the isolation contract: an
// entry without a cveID, one with an unparsable dateAdded, one with an
// unparsable dueDate and one that does not decode into the entry shape are
// each isolated through sink.RecordError (position, stable reason, SHA-256
// of the offending element) while the healthy entry still flows.
func TestNormalizeIsolatesMalformedRecords(t *testing.T) {
	const noID = `{"cveID":"","vendorProject":"Acme Corporation","dateAdded":"2026-09-01","shortDescription":"No identity."}`
	const badDate = `{"cveID":"CVE-2026-0005","dateAdded":"not-a-date","shortDescription":"Bad date."}`
	const badDue = `{"cveID":"CVE-2026-0006","dateAdded":"2026-09-01","dueDate":"tomorrow","shortDescription":"Bad due date."}`
	const notDecodable = `{"cveID":"CVE-2026-0007","dateAdded":42,"shortDescription":"Type mismatch."}`

	payload := catalogDoc("2026-09-09T04:00:00.000Z", "2026.09.09", entryA, noID, badDate, badDue, notDecodable)
	f, res := runNormalize(t, normalizeInput(payload))

	if res.Errors != 4 {
		t.Errorf("NormalizeResult.Errors = %d, want 4", res.Errors)
	}
	if want := 2; res.Records != want { // the one healthy entry (skeleton + kev evidence)
		t.Errorf("NormalizeResult.Records = %d, want %d", res.Records, want)
	}

	// The healthy entry flowed.
	if len(f.vulns) != 1 || f.vulns[0].CVEID != "CVE-2026-0001" {
		t.Fatalf("emitted vulnerabilities = %+v, want CVE-2026-0001 only", f.vulns)
	}
	if len(f.errs) != 4 {
		t.Fatalf("emitted %d RecordErrors, want 4", len(f.errs))
	}

	wantPositions := []string{"vulnerabilities[1]", "vulnerabilities[2]", "vulnerabilities[3]", "vulnerabilities[4]"}
	wantCodes := []string{reasonMissingID, reasonInvalidDate, reasonInvalidDate, reasonEntryJSON}
	wantHashes := []string{sha256Hex([]byte(noID)), sha256Hex([]byte(badDate)), sha256Hex([]byte(badDue)), sha256Hex([]byte(notDecodable))}
	for i, want := range wantPositions {
		got := f.errs[i]
		if got.Position != want {
			t.Errorf("RecordError %d position = %q, want %q", i, got.Position, want)
		}
		if !strings.HasPrefix(got.Reason, wantCodes[i]) {
			t.Errorf("RecordError %d reason = %q, want the stable code prefix %s", i, got.Reason, wantCodes[i])
		}
		if got.PayloadHash != wantHashes[i] {
			t.Errorf("RecordError %d PayloadHash = %s, want %s (SHA-256 of the offending element)", i, got.PayloadHash, wantHashes[i])
		}
	}
}

// TestNormalizeDocumentNotCatalog: a payload that is not a decodable
// catalog document is isolated whole (position "document", hashed) — a
// counted, non-fatal error, not an abort.
func TestNormalizeDocumentNotCatalog(t *testing.T) {
	f, res := runNormalize(t, normalizeInput("this is not a catalog document"))

	if res.Errors != 1 || res.Records != 0 {
		t.Fatalf("result = %+v, want 1 error and no records", res)
	}
	if len(f.errs) != 1 {
		t.Fatalf("emitted %d RecordErrors, want 1", len(f.errs))
	}
	e := f.errs[0]
	if e.Position != "document" || !strings.HasPrefix(e.Reason, reasonDocumentJSON) {
		t.Errorf("RecordError = %+v, want the document position and the document_json code", e)
	}
	if e.PayloadHash != sha256Hex([]byte("this is not a catalog document")) {
		t.Errorf("PayloadHash = %s, want the SHA-256 of the whole payload", e.PayloadHash)
	}
}

func assertStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d entries %q, want %d %q", what, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", what, i, got[i], want[i])
		}
	}
}
