package worker

// I6 exit-criteria consolidation (ARCH-007 §5/§12 NFR-010, WP-6.12 /
// DEV-134): the job→handler leg of the request → job → audit → notification
// correlation join as an `I6ExitCriteria`-named gate. The landed relay proofs
// (WP-6.08 / DEV-120) are delegated to; the notification-kind correlation is
// asserted directly (the relay re-uses the payload correlation id as the
// handler's log scope, so a notification delivery joins the request it came
// from).

import (
	"context"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/logging"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
	"github.com/brunoxpera/risksignal/internal/platform/tracing"
)

// TestI6ExitCriteriaObservabilityCorrelationJoin is the NFR-010 acceptance
// case for the worker leg: a delivered job opens a job.dispatch span whose
// trace id derives from the payload correlation id, the handler context carries
// that id (its logs join the request that enqueued the job) and a
// notification-kind event (signal.created) proves the notification leg
// specifically.
func TestI6ExitCriteriaObservabilityCorrelationJoin(t *testing.T) {
	t.Run("job dispatch span and correlation", func(t *testing.T) {
		TestRelayRecordsJobDispatchSpanAndCorrelation(t)
	})
	t.Run("dead-letter metric", func(t *testing.T) {
		TestRelayDeadLetterMetric(t)
	})
	t.Run("notification handler receives the request correlation", func(t *testing.T) {
		assertNotificationCorrelation(t)
	})
}

// assertNotificationCorrelation drives one notification-kind (signal.created)
// event through the relay and asserts the handler sees the payload's
// correlation id in its context and the correlating job.dispatch span.
func assertNotificationCorrelation(t *testing.T) {
	t.Helper()
	store := &fakeStore{events: []ClaimedEvent{{
		ID:       "ev-notif-1",
		Type:     application.EventTypeSignalCreated,
		Attempts: 1,
		Payload:  []byte(`{"type":"signal.created","signal_id":"sig-1","priority":"P1","correlation_id":"corr-notif-1"}`),
	}}}
	relay := newRelay(t, store)
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	rec := &spanRecorder{}
	relay.SetObservability(reg, tracing.New(rec))

	var seenCorrelation, spanName string
	if err := relay.Register(application.EventTypeSignalCreated, func(ctx context.Context, _ ClaimedEvent) error {
		seenCorrelation, _ = logging.CorrelationIDFrom(ctx)
		if span := tracing.SpanFromContext(ctx); span != nil {
			spanName = span.Name()
		}
		return nil
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if seenCorrelation != "corr-notif-1" {
		t.Fatalf("notification handler correlation id = %q, want the payload's corr-notif-1", seenCorrelation)
	}
	if spanName != "job.dispatch" {
		t.Fatalf("notification handler span = %q, want job.dispatch", spanName)
	}
	if len(rec.spans) != 1 {
		t.Fatalf("exported %d spans, want 1", len(rec.spans))
	}
	if want := tracing.TraceIDForCorrelation("corr-notif-1"); rec.spans[0].TraceID != want {
		t.Fatalf("span trace id = %q, want the correlation-derived %q", rec.spans[0].TraceID, want)
	}
	if len(store.acked) != 1 || store.acked[0] != "ev-notif-1" {
		t.Fatalf("acked = %v, want the delivered notification event", store.acked)
	}
}
