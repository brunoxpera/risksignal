// Package tracing provides the OpenTelemetry-compatible MVP tracer of the
// platform (concept ch. 16.1/§16.2, ARCH-007 §5, WP-6.08 / DEV-120). It is
// deliberately SDK-free: no OpenTelemetry SDK is linked or imported in the
// default build. Instead it implements the small, documented MVP scope the
// architecture locks in:
//
//   - three span kinds are instrumented — the inbound HTTP request
//     (httpapi.TraceMiddleware), the worker job dispatch (the outbox relay)
//     and the source fetch (the worker source jobs);
//   - propagation is the W3C traceparent format (version 00);
//   - the existing correlation_id is reused as the trace id — no separate
//     trace plumbing (ARCH-007 §5). A correlation id that is already a
//     canonical 32-hex trace id is used verbatim; any other correlation id
//     is hashed to a deterministic 32-hex trace id, so a request's spans
//     always share one trace id and a traceparent remains W3C-valid;
//   - spans are exported only through an Exporter wired at composition time
//     (the OTLP/HTTP adapter behind observability.otlp_endpoint). With no
//     exporter the tracer is a cheap in-process recorder: nothing leaves the
//     process (the default).
//
// The package is intentionally small — span identity, lifecycle, context
// propagation and an Exporter seam. It is not a metrics system (that is
// internal/platform/metrics) and it does not replace structured logging.
package tracing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/platform/logging"
)

// TraceparentHeader is the W3C trace context header name (RFC-shaped:
// version-traceid-spanid-flags).
const TraceparentHeader = "traceparent"

// Flags byte of the generated traceparent: sampled (0x01).
const traceFlags = "01"

// traceVersion is the W3C traceparent version this package emits.
const traceVersion = "00"

// Exporter receives a span when it ends. It is the seam of the optional OTLP
// adapter (otlp.go); a nil exporter disables export entirely.
type Exporter interface {
	Export(ctx context.Context, span EndedSpan)
}

// EndedSpan is the immutable record of a completed span, handed to the
// Exporter. Times are wall-clock (tracing durations are operational, not the
// injectable domain clock of ch. 7.2).
type EndedSpan struct {
	Name     string
	TraceID  string
	SpanID   string
	ParentID string
	Start    time.Time
	End      time.Time
	Status   int // HTTP status for request spans; 0 otherwise
	Attrs    []Attr
}

// Attr is one span attribute: a string key/value pair. Identities only —
// never a secret or free text (ch. 3.3, TR-013).
type Attr struct {
	Key   string
	Value string
}

// Tracer starts spans and, when an Exporter is wired, reports the ended ones.
// A Tracer with a nil exporter records spans in-process and exports nothing
// (the default build).
type Tracer struct {
	exporter Exporter
}

// New builds a tracer. A nil exporter disables export: spans are still
// created (so the correlation-id-as-trace-id propagation works) but nothing
// leaves the process.
func New(exporter Exporter) *Tracer {
	return &Tracer{exporter: exporter}
}

// Enabled reports whether the tracer exports ended spans.
func (t *Tracer) Enabled() bool { return t != nil && t.exporter != nil }

// spanContextKey is the unexported context key carrying the active span.
type spanContextKey struct{}

// traceIDContextKey is the unexported context key carrying an injected trace
// id (an inbound W3C traceparent adopted at the process boundary).
type traceIDContextKey struct{}

// WithTraceID returns a copy of ctx carrying traceID as the trace id of the
// next root span started from it. It is the inbound-propagation hook: the
// HTTP middleware adopts a valid inbound traceparent this way. A non-canonical
// value is ignored by Start.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDContextKey{}, traceID)
}

// TraceIDFrom returns the injected trace id of ctx, if any.
func TraceIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(traceIDContextKey{}).(string)
	return id, ok && id != ""
}

// Span is one traced operation. It is created by Start and ended exactly
// once by End; a span is not safe for concurrent use (one span belongs to one
// goroutine's operation).
type Span struct {
	name     string
	traceID  string
	spanID   string
	parentID string
	started  time.Time
	ctx      context.Context
	attrs    []Attr
	status   int
	ended    bool
	tracer   *Tracer
}

// Start opens a span named name. The trace id is the parent span's trace id
// when one is active, else the request's correlation id (via
// TraceIDForCorrelation), else a fresh random trace id. The returned context
// carries the span, so a nested Start shares the trace id and records the
// parent span id.
func (t *Tracer) Start(ctx context.Context, name string) (context.Context, *Span) {
	traceID, parentID := "", ""
	if parent := SpanFromContext(ctx); parent != nil {
		traceID = parent.traceID
		parentID = parent.spanID
	}
	if traceID == "" {
		if injected, ok := TraceIDFrom(ctx); ok && isHex(injected, 32) {
			traceID = strings.ToLower(injected)
		}
	}
	if traceID == "" {
		if cid, ok := logging.CorrelationIDFrom(ctx); ok && cid != "" {
			traceID = TraceIDForCorrelation(cid)
		}
	}
	if traceID == "" {
		traceID = randomHex(16)
	}
	s := &Span{
		name:     name,
		traceID:  traceID,
		spanID:   randomHex(8),
		parentID: parentID,
		started:  time.Now(),
		ctx:      ctx,
		tracer:   t,
	}
	return context.WithValue(ctx, spanContextKey{}, s), s
}

// SpanFromContext returns the active span of ctx, or nil.
func SpanFromContext(ctx context.Context) *Span {
	s, _ := ctx.Value(spanContextKey{}).(*Span)
	return s
}

// Name returns the span name.
func (s *Span) Name() string { return s.name }

// TraceID returns the span's trace id (32 lowercase hex).
func (s *Span) TraceID() string { return s.traceID }

// SpanID returns the span's id (16 lowercase hex).
func (s *Span) SpanID() string { return s.spanID }

// SetAttr appends one string attribute to the span.
func (s *Span) SetAttr(key, value string) {
	s.attrs = append(s.attrs, Attr{Key: key, Value: value})
}

// SetStatus records the operation's status (the HTTP status for request
// spans); 0 means "unset".
func (s *Span) SetStatus(code int) { s.status = code }

// End closes the span and, when an exporter is wired, hands the ended span to
// it. End is idempotent: a second call is a no-op.
func (s *Span) End() {
	if s == nil || s.ended {
		return
	}
	s.ended = true
	if s.tracer == nil || s.tracer.exporter == nil {
		return
	}
	end := time.Now()
	s.tracer.exporter.Export(s.ctx, EndedSpan{
		Name:     s.name,
		TraceID:  s.traceID,
		SpanID:   s.spanID,
		ParentID: s.parentID,
		Start:    s.started,
		End:      end,
		Status:   s.status,
		Attrs:    append([]Attr(nil), s.attrs...),
	})
}

// Traceparent renders the W3C traceparent header value of the span:
// version 00, the trace id, the span id and the sampled flag.
func Traceparent(s *Span) string {
	if s == nil {
		return ""
	}
	return traceVersion + "-" + s.traceID + "-" + s.spanID + "-" + traceFlags
}

// ParseTraceparent parses a W3C traceparent header value and returns its
// trace id (32 lowercase hex) when the header is well-formed and the trace id
// is valid (not all zero). It is the inbound propagation hook.
func ParseTraceparent(value string) (string, bool) {
	parts := strings.Split(value, "-")
	if len(parts) != 4 {
		return "", false
	}
	traceID := strings.ToLower(parts[1])
	if !isHex(traceID, 32) || strings.Trim(traceID, "0") == "" {
		return "", false
	}
	return traceID, true
}

// TraceIDForCorrelation maps a correlation id onto a W3C trace id (32
// lowercase hex). A canonical 32-hex correlation id that is not all zero is
// used verbatim; any other id is hashed (SHA-256, first 16 bytes) to a
// deterministic, valid trace id. The mapping is stable, so a correlation id
// always yields the same trace id.
func TraceIDForCorrelation(correlationID string) string {
	if isHex(correlationID, 32) && strings.Trim(correlationID, "0") != "" {
		return strings.ToLower(correlationID)
	}
	sum := sha256.Sum256([]byte(correlationID))
	return hex.EncodeToString(sum[:16])
}

// isHex reports whether s is exactly n lowercase-hex characters.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// randomHex returns nbytes random bytes hex-encoded (2*nbytes characters).
// crypto/rand.Read never fails on supported platforms; if it ever did, a
// guessable id would be worse than a loud failure.
func randomHex(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic("tracing: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
