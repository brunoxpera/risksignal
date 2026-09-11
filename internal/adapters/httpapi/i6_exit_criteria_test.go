package httpapi

// I6 exit-criteria consolidation (ARCH-007 §5/§12 NFR-010, WP-6.12 /
// DEV-134): the HTTP observability + request-correlation surfaces as an
// `I6ExitCriteria`-named gate — the request leg of the correlation join. Each
// subtest delegates to the landed proof (WP-6.08 / DEV-120).

import "testing"

// TestI6ExitCriteriaObservabilityRequestLeg is the NFR-010 acceptance case at
// the HTTP boundary: the /metrics handler renders the §16.2 families, the
// metrics middleware records the HTTP families for a served request, the trace
// middleware echoes a correlation-derived (or inbound-adopted) traceparent, and
// the request's effective correlation id reaches the command input (the first
// hop of request → audit → job → notification).
func TestI6ExitCriteriaObservabilityRequestLeg(t *testing.T) {
	t.Run("/metrics renders the families", func(t *testing.T) {
		TestMetricsHandlerRendersFamilies(t)
	})
	t.Run("middleware records the HTTP families", func(t *testing.T) {
		TestMetricsMiddlewareRecordsRequestFamilies(t)
	})
	t.Run("trace middleware echoes the correlation trace id", func(t *testing.T) {
		TestTraceMiddlewareEchoesCorrelationTraceID(t)
	})
	t.Run("trace middleware adopts an inbound traceparent", func(t *testing.T) {
		TestTraceMiddlewareAdoptsInboundTraceparent(t)
	})
	t.Run("request correlation id reaches the command", func(t *testing.T) {
		TestRequestCorrelationIDReachesCommand(t)
	})
	t.Run("absent inbound id is generated and still reaches the command", func(t *testing.T) {
		TestRequestCorrelationIDGeneratedWhenAbsent(t)
	})
}
