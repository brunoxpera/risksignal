package tracing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/platform/logging"
)

// recordingExporter captures the ended spans it is handed.
type recordingExporter struct {
	spans []EndedSpan
}

func (r *recordingExporter) Export(_ context.Context, span EndedSpan) {
	r.spans = append(r.spans, span)
}

func TestTraceIDForCorrelation(t *testing.T) {
	canonical := "0123456789abcdef0123456789abcdef"
	if got := TraceIDForCorrelation(canonical); got != canonical {
		t.Errorf("canonical correlation id changed: %q", got)
	}
	// A non-canonical correlation id is hashed to a valid, 32-hex, stable id.
	derived := TraceIDForCorrelation("corr-42")
	if len(derived) != 32 || !isHex(derived, 32) {
		t.Fatalf("derived trace id %q is not 32 lowercase hex", derived)
	}
	if again := TraceIDForCorrelation("corr-42"); again != derived {
		t.Errorf("derivation is not stable: %q vs %q", derived, again)
	}
	if derived == canonical {
		t.Error("unrelated ids must not collide")
	}
}

func TestStartUsesCorrelationIDAsTraceID(t *testing.T) {
	ctx := logging.WithCorrelationID(context.Background(), "corr-42")
	tr := New(nil)
	_, span := tr.Start(ctx, "http.request")
	if want := TraceIDForCorrelation("corr-42"); span.TraceID() != want {
		t.Fatalf("trace id = %q, want the correlation-derived %q", span.TraceID(), want)
	}
	if len(span.SpanID()) != 16 {
		t.Fatalf("span id = %q, want 16 hex chars", span.SpanID())
	}
}

func TestChildSpanSharesTraceIDAndRecordsParent(t *testing.T) {
	ctx := logging.WithCorrelationID(context.Background(), "corr-1")
	tr := New(nil)
	parentCtx, parent := tr.Start(ctx, "http.request")
	_, child := tr.Start(parentCtx, "job.dispatch")

	if child.TraceID() != parent.TraceID() {
		t.Fatalf("child trace id %q != parent %q", child.TraceID(), parent.TraceID())
	}
	if child.parentID != parent.SpanID() {
		t.Fatalf("child parent id %q != parent span id %q", child.parentID, parent.SpanID())
	}
	if child.SpanID() == parent.SpanID() {
		t.Fatal("child and parent must have distinct span ids")
	}
}

func TestTraceparentRoundTrip(t *testing.T) {
	tr := New(nil)
	_, span := tr.Start(logging.WithCorrelationID(context.Background(), "corr-9"), "http.request")
	tp := Traceparent(span)

	parts := strings.Split(tp, "-")
	if len(parts) != 4 || parts[0] != "00" || parts[1] != span.TraceID() || parts[2] != span.SpanID() || parts[3] != "01" {
		t.Fatalf("traceparent %q is not version-00 traceid-spanid-01", tp)
	}
	got, ok := ParseTraceparent(tp)
	if !ok || got != span.TraceID() {
		t.Fatalf("ParseTraceparent(%q) = %q, %v; want the trace id", tp, got, ok)
	}
	if _, ok := ParseTraceparent("garbage"); ok {
		t.Fatal("ParseTraceparent accepted a malformed header")
	}
	if _, ok := ParseTraceparent("00-" + strings.Repeat("0", 32) + "-0123456789abcdef-01"); ok {
		t.Fatal("ParseTraceparent accepted an all-zero trace id")
	}
}

func TestNoExporterByDefault(t *testing.T) {
	tr := New(nil)
	if tr.Enabled() {
		t.Fatal("a tracer with no exporter must report Enabled() == false")
	}
	// Start/End with no exporter is a silent no-op beyond the in-process span.
	_, span := tr.Start(context.Background(), "http.request")
	span.End()
	span.End() // idempotent
}

func TestExporterReceivesEndedSpan(t *testing.T) {
	rec := &recordingExporter{}
	tr := New(rec)
	if !tr.Enabled() {
		t.Fatal("Enabled() = false with an exporter wired")
	}
	ctx := logging.WithCorrelationID(context.Background(), "corr-ex")
	_, span := tr.Start(ctx, "http.request")
	span.SetAttr("method", "GET")
	span.SetStatus(http.StatusOK)
	span.End()
	span.End() // a second End must not export again

	if len(rec.spans) != 1 {
		t.Fatalf("exported %d spans, want 1", len(rec.spans))
	}
	got := rec.spans[0]
	if got.Name != "http.request" || got.TraceID != span.TraceID() || got.Status != http.StatusOK {
		t.Fatalf("ended span = %+v", got)
	}
	if len(got.Attrs) != 1 || got.Attrs[0].Key != "method" || got.Attrs[0].Value != "GET" {
		t.Fatalf("attrs = %+v", got.Attrs)
	}
}

// TestOTLPExporterPostsJSON proves the OTLP/HTTP adapter POSTs a JSON
// ExportTraceServiceRequest to <endpoint>/v1/traces.
func TestOTLPExporterPostsJSON(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := New(NewOTLPExporter(srv.URL, "risksignal-test"))
	_, span := tr.Start(logging.WithCorrelationID(context.Background(), "corr-otlp"), "http.request")
	span.End()

	if gotPath != "/v1/traces" {
		t.Fatalf("export path = %q, want /v1/traces", gotPath)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(gotBody), &decoded); err != nil {
		t.Fatalf("OTLP body is not JSON: %v\n%s", err, gotBody)
	}
	if !strings.Contains(gotBody, span.TraceID()) {
		t.Errorf("OTLP body does not carry the trace id: %s", gotBody)
	}
	if !strings.Contains(gotBody, "service.name") {
		t.Errorf("OTLP body does not carry the resource attribute: %s", gotBody)
	}
}

func TestTracerNilSafety(t *testing.T) {
	var tr *Tracer
	if tr.Enabled() {
		t.Fatal("nil tracer must report Enabled() == false")
	}
}

// TestSpanTimesAreOrdered guards the started/ended time ordering the exporter
// relies on.
func TestSpanTimesAreOrdered(t *testing.T) {
	rec := &recordingExporter{}
	tr := New(rec)
	_, span := tr.Start(context.Background(), "source.fetch")
	time.Sleep(time.Millisecond)
	span.End()
	if len(rec.spans) != 1 {
		t.Fatalf("exported %d spans, want 1", len(rec.spans))
	}
	if !rec.spans[0].End.After(rec.spans[0].Start) {
		t.Fatalf("span End %v is not after Start %v", rec.spans[0].End, rec.spans[0].Start)
	}
}
