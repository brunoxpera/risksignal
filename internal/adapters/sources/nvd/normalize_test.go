package nvd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// Realistic API 2.0 fixture pages (shape verified against the live API:
// page.vulnerabilities[] elements wrap the record in {"cve": {…}}, V3
// metrics carry baseSeverity inside cvssData, V2 on the metric object).
// entry1 is pretty-printed on purpose — the normaliser must compact it, so
// the canonical nvd_statement does not depend on the source's whitespace.
const normalizeEntry1 = `{
      "cve": {
        "id": "CVE-2026-0001",
        "descriptions": [
          {"lang": "en", "value": "Stack overflow in the widget parser allows remote code execution."},
          {"lang": "de", "value": "Stapelueberlauf im Widget-Parser erlaubt Remote-Codeausfuehrung."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
              },
              "exploitabilityScore": 3.9,
              "impactScore": 5.9
            }
          ],
          "cvssMetricV2": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "2.0",
                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "baseScore": 7.5
              },
              "baseSeverity": "HIGH"
            }
          ]
        },
        "configurations": [
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*",
                    "matchCriteriaId": "ABCDEF12-3456-7890-ABCD-EF1234567890"
                  }
                ]
              }
            ],
            "operator": "OR"
          }
        ],
        "references": [
          {"url": "https://example.com/advisory/1", "source": "cve@mitre.org", "tags": ["Vendor Advisory"]},
          {"url": "https://example.com/advisory/2", "source": "cve@mitre.org", "tags": ["Exploit", "Patch"]},
          {"url": "", "source": "cve@mitre.org", "tags": ["Broken"]}
        ]
      }
    }`

// normalizeEntry2 carries no English description (fall back to the first),
// only a V2 metric (severity on the metric object) and no configurations or
// references.
const normalizeEntry2 = `{"cve":{"id":"CVE-2026-0002","descriptions":[{"lang":"fr","value":"Pas de description en anglais."}],"metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:N/I:N/A:P","baseScore":5.0},"baseSeverity":"MEDIUM"}]}}}`

// normalizeEntry3 carries no metrics at all: no cvss summary, no cvss
// evidence.
const normalizeEntry3 = `{"cve":{"id":"CVE-2026-0003","descriptions":[{"lang":"en","value":"Format string issue with no published metrics."}]}}`

func normalizePage(vulns ...string) string {
	return `{"resultsPerPage":2000,"startIndex":0,"totalResults":` + strconv.Itoa(len(vulns)) + `,"vulnerabilities":[` + strings.Join(vulns, ",") + `]}`
}

// normalizeInput builds the NormalizeInput of the fixtures (raw record id
// and content hash are opaque to the normaliser).
func normalizeInput(payload string) application.NormalizeInput {
	return application.NormalizeInput{
		RawRecordID: "raw-nvd-1",
		Payload:     []byte(payload),
		ContentHash: "fixture",
	}
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

// runNormalize runs one pass over payload and fails the test on an
// unexpected error.
func runNormalize(t *testing.T, payload string) (*fakeNormalizeSink, application.NormalizeResult) {
	t.Helper()
	f := &fakeNormalizeSink{}
	res, err := new(Adapter).Normalize(context.Background(), normalizeInput(payload), f)
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}
	return f, res
}

// evidenceValueHash is the canonical SHA-256 of one evidence value — the
// value hash the persistence layer derives from the marshalled value (UQ
// (raw_record_id, type, value_hash)).
func evidenceValueHash(e domain.Evidence) string {
	b, _ := json.Marshal(e.Value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON compacts b for byte-exact comparisons.
func canonicalJSON(b []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return string(b)
	}
	return buf.String()
}

// TestNormalizeEmitsDomainRecords drives one two-page pass and asserts the
// full emission: one vulnerability per CVE with the normalised fields
// (cve_id, summary = the English description, cvss from the first V31
// metric with the V2 fallback, references, raw cpe_config), plus the
// nvd_statement and cvss evidences of each record, each vulnerability
// emitted before its evidences (the sink attribution contract).
func TestNormalizeEmitsDomainRecords(t *testing.T) {
	payload := normalizePage(normalizeEntry1, normalizeEntry2) + "\n" + normalizePage(normalizeEntry3)
	f, res := runNormalize(t, payload)

	if res.Errors != 0 {
		t.Errorf("NormalizeResult.Errors = %d, want 0", res.Errors)
	}
	if want := 3 + 3 + 2; res.Records != want { // 3 vulns + 3 statements + 2 cvss evidences
		t.Errorf("NormalizeResult.Records = %d, want %d", res.Records, want)
	}

	// Emission order: each record's vulnerability precedes its evidences.
	wantEvents := []string{
		"vulnerability:CVE-2026-0001",
		"evidence:nvd_statement:CVE-2026-0001",
		"evidence:cvss:CVE-2026-0001",
		"vulnerability:CVE-2026-0002",
		"evidence:nvd_statement:CVE-2026-0002",
		"evidence:cvss:CVE-2026-0002",
		"vulnerability:CVE-2026-0003",
		"evidence:nvd_statement:CVE-2026-0003",
	}
	assertStrings(t, "emission order", f.events, wantEvents)

	if len(f.vulns) != 3 {
		t.Fatalf("emitted %d vulnerabilities, want 3", len(f.vulns))
	}

	// CVE-2026-0001: the full record — English summary/description, V31
	// metrics, references (the URL-less link dropped), raw cpe_config.
	v1 := f.vulns[0]
	if v1.CVEID != "CVE-2026-0001" || v1.Summary != "Stack overflow in the widget parser allows remote code execution." {
		t.Errorf("vulnerability 1 cve_id/summary = %q/%q, want CVE-2026-0001 with the English description", v1.CVEID, v1.Summary)
	}
	if v1.Description != v1.Summary {
		t.Errorf("description = %q, want the English description", v1.Description)
	}
	if v1.CVSS == nil {
		t.Fatalf("vulnerability 1 cvss = nil, want the V31 summary")
	}
	if v1.CVSS.Version != "3.1" || v1.CVSS.BaseScore != 9.8 || v1.CVSS.BaseSeverity != "critical" || v1.CVSS.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("cvss = %+v, want version 3.1 score 9.8 severity critical and the vector", *v1.CVSS)
	}
	wantRefs := []domain.Reference{
		{URL: "https://example.com/advisory/1", Source: "cve@mitre.org", Tags: []string{"Vendor Advisory"}},
		{URL: "https://example.com/advisory/2", Source: "cve@mitre.org", Tags: []string{"Exploit", "Patch"}},
	}
	assertReferences(t, v1.References, wantRefs)
	wantCfg := `[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*","matchCriteriaId":"ABCDEF12-3456-7890-ABCD-EF1234567890"}]}],"operator":"OR"}]`
	if got := canonicalJSON(v1.CPECfg.(json.RawMessage)); got != wantCfg {
		t.Errorf("cpe_config = %s, want the raw configurations block", got)
	}

	// CVE-2026-0002: no English description — summary falls back to the
	// first one; V2 metric read with the severity from the metric object.
	v2 := f.vulns[1]
	if v2.CVEID != "CVE-2026-0002" || v2.Summary != "Pas de description en anglais." {
		t.Errorf("vulnerability 2 cve_id/summary = %q/%q, want the first description", v2.CVEID, v2.Summary)
	}
	if v2.CVSS == nil || v2.CVSS.Version != "2.0" || v2.CVSS.BaseScore != 5.0 || v2.CVSS.BaseSeverity != "medium" || v2.CVSS.Vector != "AV:N/AC:L/Au:N/C:N/I:N/A:P" {
		t.Errorf("cvss 2 = %+v, want the V2 summary with severity medium", v2.CVSS)
	}
	if v2.CPECfg != nil || v2.References != nil {
		t.Errorf("vulnerability 2 carries cpe_config %v / references %v, want both absent", v2.CPECfg, v2.References)
	}

	// CVE-2026-0003: no metrics — no cvss summary, no cvss evidence.
	v3 := f.vulns[2]
	if v3.CVEID != "CVE-2026-0003" || v3.CVSS != nil {
		t.Errorf("vulnerability 3 = %+v, want CVE-2026-0003 without cvss", v3)
	}

	// Evidences: three nvd_statements (canonical compacted record excerpt),
	// two cvss values with the {cve_id, base_score, severity, vector,
	// version} shape.
	if len(f.evids) != 5 {
		t.Fatalf("emitted %d evidences, want 5", len(f.evids))
	}
	for i, e := range f.evids {
		switch e.Type {
		case domain.EvidenceTypeNVDStatement:
			var st nvdStatementValue
			if err := json.Unmarshal(mustMarshal(t, e.Value), &st); err != nil {
				t.Fatalf("evidence %d: unmarshal nvd_statement value: %v", i, err)
			}
			wantStatement := []string{normalizeEntry1, normalizeEntry2, normalizeEntry3}[i/2]
			want := canonicalJSON([]byte(wantStatement))
			if st.Statement != want {
				t.Errorf("evidence %d statement = %s, want the compacted record excerpt", i, st.Statement)
			}
		case domain.EvidenceTypeCVSS:
			var cv cvssEvidenceValue
			if err := json.Unmarshal(mustMarshal(t, e.Value), &cv); err != nil {
				t.Fatalf("evidence %d: unmarshal cvss value: %v", i, err)
			}
			if cv.CveID == "" || cv.Version == "" || cv.Severity == "" || cv.Vector == "" {
				t.Errorf("evidence %d cvss value = %+v, want the complete {cve_id, base_score, severity, vector, version}", i, cv)
			}
		default:
			t.Errorf("evidence %d has unexpected type %q", i, e.Type)
		}
	}
}

// TestNormalizePicksV30WhenNoV31 pins the metric fallback ladder: without a
// V31 list the first V30 metric wins over the V2 one.
func TestNormalizePicksV30WhenNoV31(t *testing.T) {
	entry := `{"cve":{"id":"CVE-2026-0006","descriptions":[{"lang":"en","value":"V30 only record."}],"metrics":{"cvssMetricV30":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.0","vectorString":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.1,"baseSeverity":"CRITICAL"}}],"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P","baseScore":7.5},"baseSeverity":"HIGH"}]}}}`
	f, _ := runNormalize(t, normalizePage(entry))
	if len(f.vulns) != 1 || f.vulns[0].CVSS == nil {
		t.Fatalf("want one vulnerability with a cvss summary, got %+v", f.vulns)
	}
	cv := f.vulns[0].CVSS
	if cv.Version != "3.0" || cv.BaseScore != 9.1 || cv.BaseSeverity != "critical" {
		t.Errorf("cvss = %+v, want the V30 summary (9.1, critical)", *cv)
	}
}

// TestNormalizeIsolatesMalformedRecords proves the isolation contract: a
// CVE without an id and a structurally broken entry are each isolated
// through sink.RecordError (position, stable reason, SHA-256 of the
// offending element) while the other records — on the same and on the next
// page — still flow.
func TestNormalizeIsolatesMalformedRecords(t *testing.T) {
	const noID = `{"cve":{"descriptions":[{"lang":"en","value":"A record without identity."}]}}`
	const badShape = `{"cve":{"id":"CVE-2026-0005","metrics":{"cvssMetricV31":"not-an-array"}}}`
	const goodA = `{"cve":{"id":"CVE-2026-0007","descriptions":[{"lang":"en","value":"Healthy record on the broken page."}]}}`
	const goodB = `{"cve":{"id":"CVE-2026-0008","descriptions":[{"lang":"en","value":"Healthy record on the next page."}]}}`

	payload := normalizePage(goodA, noID, badShape) + "\n" + normalizePage(goodB)
	f, res := runNormalize(t, payload)

	if res.Errors != 2 {
		t.Errorf("NormalizeResult.Errors = %d, want 2", res.Errors)
	}
	if want := 2 + 2; res.Records != want { // 2 healthy vulns + their 2 statements
		t.Errorf("NormalizeResult.Records = %d, want %d", res.Records, want)
	}

	// Both healthy records flowed, in order, across the page boundary.
	if len(f.vulns) != 2 || f.vulns[0].CVEID != "CVE-2026-0007" || f.vulns[1].CVEID != "CVE-2026-0008" {
		t.Fatalf("emitted vulnerabilities = %+v, want CVE-2026-0007 and CVE-2026-0008", f.vulns)
	}
	if len(f.errs) != 2 {
		t.Fatalf("emitted %d RecordErrors, want 2", len(f.errs))
	}

	wantErrs := []application.RecordError{
		{Position: "page 1 vulnerabilities[1]", Reason: reasonMissingID + ": the record carries no cve.id", PayloadHash: sha256Hex([]byte(noID))},
		{Position: "page 1 vulnerabilities[2]", Reason: reasonEntryJSON + ": json: cannot unmarshal string into Go struct field nvdEntry.cve.metrics.cvssMetricV31 of type []nvd.nvdCVSSMetric", PayloadHash: sha256Hex([]byte(badShape))},
	}
	for i, want := range wantErrs {
		got := f.errs[i]
		if got.Position != want.Position || got.Reason != want.Reason {
			t.Errorf("RecordError %d = position %q reason %q, want %q / %q", i, got.Position, got.Reason, want.Position, want.Reason)
		}
		if got.PayloadHash != want.PayloadHash {
			t.Errorf("RecordError %d PayloadHash = %s, want %s (SHA-256 of the offending element)", i, got.PayloadHash, want.PayloadHash)
		}
	}
	if !strings.HasPrefix(f.errs[0].Reason, reasonMissingID) || !strings.HasPrefix(f.errs[1].Reason, reasonEntryJSON) {
		t.Errorf("reasons = %q / %q, want the stable codes %s and %s", f.errs[0].Reason, f.errs[1].Reason, reasonMissingID, reasonEntryJSON)
	}
}

// TestNormalizeDeterministicEmission proves that one payload normalises to
// one canonical emission: two passes over the same fixture produce the
// identical event stream and identical value hashes (the input of the UQ
// (raw_record_id, type, value_hash) dedupe) — pinned to golden values so
// any change to the canonical shapes or the hashing input fails here.
func TestNormalizeDeterministicEmission(t *testing.T) {
	payload := normalizePage(normalizeEntry1, normalizeEntry2) + "\n" + normalizePage(normalizeEntry3)

	first, res1 := runNormalize(t, payload)
	second, res2 := runNormalize(t, payload)

	if res1.Records != res2.Records || res1.Errors != res2.Errors {
		t.Errorf("results differ between passes: %+v vs %+v", res1, res2)
	}
	if len(first.evids) != len(second.evids) || len(first.vulns) != len(second.vulns) || len(first.errs) != len(second.errs) {
		t.Fatalf("emission sizes differ between passes")
	}
	for i := range first.events {
		if first.events[i] != second.events[i] {
			t.Fatalf("event %d differs between passes: %q vs %q", i, first.events[i], second.events[i])
		}
	}
	golden := []string{
		"01b9f00b876a59837099a6040bfd893e0a77ffffea1203283b1532ba0d02041d",
		"b0decd7fa46823352ffc3a107511609bd3387258d59cbe2931fde89d20ec3be1",
		"77d671bb9857a322ecdb25db10329ea55ce1f116c3c58f7722493fe714e20bfe",
		"f8dc80ea96c8b454c6d5538419656f498286cdc5e4006ccfc095d06bce300dbc",
		"394bf13b65a894eb10607aa4c72e18e1dd822df8d1de8a612d4a8203bb7abd90",
	}
	for i, e := range first.evids {
		got := evidenceValueHash(e)
		if got != golden[i] {
			t.Errorf("evidence %d (%s) value hash = %s, want %s", i, e.Type, got, golden[i])
		}
		if second.evids[i].Type != e.Type || evidenceValueHash(second.evids[i]) != got {
			t.Errorf("evidence %d hash is not stable across passes", i)
		}
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

func assertReferences(t *testing.T, got, want []domain.Reference) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("references: got %+v, want %+v", got, want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.URL != w.URL || g.Source != w.Source || !equalStrings(g.Tags, w.Tags) {
			t.Errorf("reference %d = %+v, want %+v", i, g, w)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %v: %v", v, err)
	}
	return b
}
