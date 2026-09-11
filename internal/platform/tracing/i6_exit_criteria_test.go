package tracing

// I6 exit-criteria consolidation (ARCH-007 §5/§12 NFR-010, WP-6.12 /
// DEV-134): the correlation-id-as-trace-id mapping and the config-gated OTLP
// export as an `I6ExitCriteria`-named gate (the "OTLP spans" half of NFR-010).
// Each subtest delegates to the landed proof (WP-6.08 / DEV-120).

import "testing"

// TestI6ExitCriteriaOTLPSpans is the NFR-010 trace acceptance case: the
// correlation id is used as the trace id (a child span shares it and records
// its parent), spans are exported only through a wired exporter (off by
// default), and the OTLP/HTTP adapter encodes an ended span as a
// ExportTraceServiceRequest POST.
func TestI6ExitCriteriaOTLPSpans(t *testing.T) {
	t.Run("correlation id becomes the trace id", func(t *testing.T) {
		TestStartUsesCorrelationIDAsTraceID(t)
	})
	t.Run("child span shares the trace id and records its parent", func(t *testing.T) {
		TestChildSpanSharesTraceIDAndRecordsParent(t)
	})
	t.Run("traceparent round-trips", func(t *testing.T) {
		TestTraceparentRoundTrip(t)
	})
	t.Run("no exporter by default", func(t *testing.T) {
		TestNoExporterByDefault(t)
	})
	t.Run("exporter receives the ended span", func(t *testing.T) {
		TestExporterReceivesEndedSpan(t)
	})
	t.Run("OTLP exporter posts JSON", func(t *testing.T) {
		TestOTLPExporterPostsJSON(t)
	})
}
