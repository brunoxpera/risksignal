package tracing

// The optional OTLP/HTTP exporter (ARCH-007 §5, WP-6.08 / DEV-120). It is a
// thin adapter over the standard library — no OpenTelemetry SDK is linked in
// the default build. It is only wired when observability.otlp_endpoint is
// set; with the endpoint empty the tracer has no exporter and nothing leaves
// the process. The exporter encodes one span as an OTLP/HTTP JSON request
// (ExportTraceServiceRequest) and POSTs it to <endpoint>/v1/traces.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// exportTimeout bounds one OTLP export call. Tracing must never block the
// traced operation: a slow or dead collector is dropped, not waited on.
const exportTimeout = 5 * time.Second

// OTLPExporter posts ended spans to an OTLP/HTTP endpoint as JSON.
type OTLPExporter struct {
	endpoint string
	client   *http.Client
	service  string
}

// NewOTLPExporter builds an exporter posting to endpoint (e.g.
// "http://collector:4318"). The trailing slash is optional. service is
// recorded as the resource attribute service.name.
func NewOTLPExporter(endpoint, service string) *OTLPExporter {
	return &OTLPExporter{
		endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Timeout: exportTimeout},
		service:  service,
	}
}

// Export encodes span as an OTLP/HTTP JSON request and POSTs it. An export
// failure is deliberately swallowed: tracing is best-effort and must never
// affect the traced operation.
func (e *OTLPExporter) Export(ctx context.Context, span EndedSpan) {
	body, err := json.Marshal(otlpRequest(e.service, span))
	if err != nil {
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, exportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, e.endpoint+"/v1/traces", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// otlpRequest shapes one span as an ExportTraceServiceRequest.
func otlpRequest(service string, span EndedSpan) map[string]any {
	attrs := make([]map[string]any, 0, len(span.Attrs))
	for _, a := range span.Attrs {
		attrs = append(attrs, map[string]any{"key": a.Key, "value": map[string]any{"stringValue": a.Value}})
	}
	resourceAttrs := []map[string]any{}
	if service != "" {
		resourceAttrs = append(resourceAttrs, map[string]any{
			"key": "service.name", "value": map[string]any{"stringValue": service},
		})
	}
	otlpSpan := map[string]any{
		"traceId":           span.TraceID,
		"spanId":            span.SpanID,
		"name":              span.Name,
		"kind":              2, // SPAN_KIND_SERVER for request spans; harmless for the MVP
		"startTimeUnixNano": strconv.FormatInt(span.Start.UnixNano(), 10),
		"endTimeUnixNano":   strconv.FormatInt(span.End.UnixNano(), 10),
		"attributes":        attrs,
	}
	if span.ParentID != "" {
		otlpSpan["parentSpanId"] = span.ParentID
	}
	if span.Status != 0 {
		otlpSpan["status"] = map[string]any{"code": otlpStatusCode(span.Status)}
	}
	return map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource":   map[string]any{"attributes": resourceAttrs},
				"scopeSpans": []map[string]any{{"scope": map[string]any{"name": "risksignal"}, "spans": []map[string]any{otlpSpan}}},
			},
		},
	}
}

// otlpStatusCode maps an HTTP status onto the OTLP status code: 2 (ERROR)
// for 5xx, 1 (OK) otherwise.
func otlpStatusCode(httpStatus int) int {
	if httpStatus >= 500 {
		return 2
	}
	return 1
}
