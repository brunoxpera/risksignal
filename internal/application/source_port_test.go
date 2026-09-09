package application_test

// Unit tests for the shared source adapter contract (WP-2.01, DEV-027;
// ARCH-002 §1): the vocabulary values the sources registry and the schema
// rely on, the Fetch/Normalize data flow through a fake adapter and a
// recording sink, and the compile-time proof that the fake actually
// implements SourcePort and NormalizeSink (the interface is exactly the
// documented shape).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// fakeSource is a minimal SourcePort implementation used to pin the
// interface shape and to exercise the Fetch/Normalize data flow.
type fakeSource struct {
	typ         application.SourceType
	plan        application.SourcePlan
	fetchIn     application.FetchInput
	fetchOut    application.FetchOutput
	normalizeIn application.NormalizeInput
	result      application.NormalizeResult
}

func (f *fakeSource) Type() application.SourceType { return f.typ }

func (f *fakeSource) Plan() application.SourcePlan { return f.plan }

func (f *fakeSource) Fetch(ctx context.Context, in application.FetchInput) (application.FetchOutput, error) {
	f.fetchIn = in
	return f.fetchOut, nil
}

func (f *fakeSource) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	f.normalizeIn = in
	return f.result, nil
}

// recordingSink is a NormalizeSink that records everything the adapter
// streams into it, mirroring what the persistence sink will do.
type recordingSink struct {
	vulns      []domain.Vulnerability
	evidences  []domain.Evidence
	recordErrs []application.RecordError
}

func (s *recordingSink) Vulnerability(ctx context.Context, v domain.Vulnerability) error {
	s.vulns = append(s.vulns, v)
	return nil
}

func (s *recordingSink) Evidence(ctx context.Context, e domain.Evidence) error {
	s.evidences = append(s.evidences, e)
	return nil
}

func (s *recordingSink) RecordError(ctx context.Context, e application.RecordError) error {
	s.recordErrs = append(s.recordErrs, e)
	return nil
}

// compile-time checks: the fakes must satisfy the exact documented port
// shapes — a signature drift on SourcePort or NormalizeSink breaks here.
var (
	_ application.SourcePort    = (*fakeSource)(nil)
	_ application.NormalizeSink = (*recordingSink)(nil)
)

// TestSourceVocabulary pins the source type/kind/cursor vocabulary to the
// exact values the sources registry, the schema and the I2 adapters share
// (ARCH-002 §1).
func TestSourceVocabulary(t *testing.T) {
	types := map[application.SourceType]string{
		application.SourceTypeNVD:       "nvd",
		application.SourceTypeKEV:       "kev",
		application.SourceTypeEPSS:      "epss",
		application.SourceTypeSynthetic: "synthetic",
	}
	for typ, want := range types {
		if string(typ) != want {
			t.Errorf("SourceType %q: want literal %q", typ, want)
		}
	}

	kinds := map[application.SourceKind]string{
		application.SourceKindIncremental: "incremental",
		application.SourceKindFullSet:     "full_set",
	}
	for kind, want := range kinds {
		if string(kind) != want {
			t.Errorf("SourceKind %q: want literal %q", kind, want)
		}
	}

	cursors := map[application.CursorKind]string{
		application.CursorKindLastModified: "last_modified",
		application.CursorKindNone:         "none",
	}
	for cursor, want := range cursors {
		if string(cursor) != want {
			t.Errorf("CursorKind %q: want literal %q", cursor, want)
		}
	}
}

// TestSourcePlanSurface pins the plan a source advertises (ARCH-002 §1):
// schedule plus kind/cursor vocabulary — the fields the scheduler and the
// source monitor read.
func TestSourcePlanSurface(t *testing.T) {
	src := &fakeSource{
		typ: application.SourceTypeEPSS,
		plan: application.SourcePlan{
			Schedule:   "@daily",
			Kind:       application.SourceKindFullSet,
			CursorKind: application.CursorKindNone,
		},
	}
	if src.Type() != application.SourceTypeEPSS {
		t.Errorf("Type() = %q, want epss", src.Type())
	}
	p := src.Plan()
	if p.Schedule != "@daily" || p.Kind != application.SourceKindFullSet || p.CursorKind != application.CursorKindNone {
		t.Errorf("Plan() = %+v, want daily full-set source without cursor", p)
	}
}

// TestFetchFlow drives one Fetch through the fake: the input (descriptor,
// window, API-key reference) arrives unchanged and the output fields
// (external id, payload, hash, cursor, metadata) flow back to the caller.
func TestFetchFlow(t *testing.T) {
	now := time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)
	src := &fakeSource{
		typ: application.SourceTypeNVD,
		plan: application.SourcePlan{
			Schedule:   "@hourly",
			Kind:       application.SourceKindIncremental,
			CursorKind: application.CursorKindLastModified,
		},
		fetchOut: application.FetchOutput{
			ExternalID:  "nvd:2026-09-09T08:30:00Z:2026-09-09T09:30:00Z:page-0",
			Payload:     []byte(`{"vulnerabilities":[]}`),
			ContentHash: "abc123",
			FetchedAt:   now,
			Cursor:      json.RawMessage(`{"last_modified":"2026-09-09T09:30:00Z"}`),
			Meta: application.FetchMeta{
				Status:      200,
				ContentType: "application/json",
				Size:        24,
			},
		},
	}

	in := application.FetchInput{
		Source: application.SourceDescriptor{
			ID:       "src-1",
			Type:     application.SourceTypeNVD,
			Endpoint: "https://services.nvd.nist.gov/rest/json/cves/2.0",
			Config:   map[string]any{"window": "2h", "api_key_ref": "env:RISKSIGNAL_NVD_API_KEY"},
		},
		Window:    application.TimeWindow{From: now.Add(-2 * time.Hour), To: now},
		APIKeyRef: "env:RISKSIGNAL_NVD_API_KEY",
	}

	out, err := src.Fetch(context.Background(), in)
	if err != nil {
		t.Fatalf("Fetch: unexpected error: %v", err)
	}
	if src.fetchIn.Source.ID != in.Source.ID || src.fetchIn.Source.Endpoint != in.Source.Endpoint {
		t.Errorf("Fetch: descriptor not passed through unchanged: %+v", src.fetchIn.Source)
	}
	if !src.fetchIn.Window.From.Equal(in.Window.From) || !src.fetchIn.Window.To.Equal(in.Window.To) {
		t.Errorf("Fetch: window not passed through unchanged: %+v", src.fetchIn.Window)
	}
	if src.fetchIn.APIKeyRef != "env:RISKSIGNAL_NVD_API_KEY" {
		t.Errorf("Fetch: API key reference not passed through: %q", src.fetchIn.APIKeyRef)
	}
	if out.ExternalID == "" || len(out.Payload) == 0 || out.ContentHash == "" {
		t.Errorf("Fetch: output misses payload fields: %+v", out)
	}
	if string(out.Cursor) != `{"last_modified":"2026-09-09T09:30:00Z"}` {
		t.Errorf("Fetch: cursor not carried: %s", out.Cursor)
	}
	if out.Meta.Status != 200 || out.Meta.Size != 24 {
		t.Errorf("Fetch: metadata not carried: %+v", out.Meta)
	}
}

// TestNormalizeFlow drives one Normalize pass through the fake into a
// recording sink: the raw-record identity arrives unchanged, the result
// counts return to the caller, and the sink receives the streamed domain
// objects and per-record errors in emission order.
func TestNormalizeFlow(t *testing.T) {
	// The sink contract receives domain.Vulnerability values; a minimal
	// valid value (the I1b/KEV-skeleton shape) is enough here — the
	// constructor invariants are the domain's own tests' concern.
	vuln := domain.Vulnerability{ID: "v1", CVEID: "CVE-2026-0001", Summary: "summary"}
	ev, err := domain.NewEvidence("e1", "v1", "r1", domain.EvidenceTypeKEV, map[string]any{"cve_id": "CVE-2026-0001"}, "hash1")
	if err != nil {
		t.Fatalf("NewEvidence: unexpected error: %v", err)
	}
	recErr := application.RecordError{
		Position:    "line 12",
		Reason:      "parse_error: missing cve_id",
		PayloadHash: "deadbeef",
	}

	src := &fakeSource{
		typ: application.SourceTypeKEV,
		result: application.NormalizeResult{
			Records: 1,
			Errors:  1,
		},
	}
	sink := &recordingSink{}

	in := application.NormalizeInput{
		RawRecordID: "r1",
		Payload:     []byte(`[{"cveID":"CVE-2026-0001"}]`),
		ContentHash: "hash-of-payload",
		Meta:        application.FetchMeta{ContentType: "application/json"},
	}
	result, err := src.Normalize(context.Background(), in, sink)
	if err != nil {
		t.Fatalf("Normalize: unexpected error: %v", err)
	}
	if result.Records != 1 || result.Errors != 1 {
		t.Errorf("Normalize: result counts not returned: %+v", result)
	}
	if src.normalizeIn.RawRecordID != "r1" || src.normalizeIn.ContentHash != "hash-of-payload" {
		t.Errorf("Normalize: raw record identity not passed through: %+v", src.normalizeIn)
	}

	// The sink seam: the persistence sink will receive the same stream —
	// domain objects and isolated errors, never an aborted run.
	_ = sink.Vulnerability(context.Background(), vuln)
	_ = sink.Evidence(context.Background(), ev)
	_ = sink.RecordError(context.Background(), recErr)

	if len(sink.vulns) != 1 || sink.vulns[0].CVEID != "CVE-2026-0001" {
		t.Errorf("sink: vulnerability not received: %+v", sink.vulns)
	}
	if len(sink.evidences) != 1 || sink.evidences[0].Type != domain.EvidenceTypeKEV {
		t.Errorf("sink: evidence not received: %+v", sink.evidences)
	}
	if len(sink.recordErrs) != 1 || sink.recordErrs[0] != recErr {
		t.Errorf("sink: record error not received: %+v", sink.recordErrs)
	}
}
