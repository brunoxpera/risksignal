package worker

// Unit tests of the relay's observability wiring (ARCH-007 §5, WP-6.08 /
// DEV-120): the job-dispatch metrics (attempts, dead letters, queue depth),
// the job-dispatch span whose trace id is the job payload's correlation id and
// the correlation-id propagation into the handler context (so a job's logs
// carry the same correlation id as the request that enqueued it).

import (
	"context"
	"testing"

	"github.com/brunoxpera/risksignal/internal/platform/logging"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
	"github.com/brunoxpera/risksignal/internal/platform/tracing"
)

// spanRecorder captures ended spans for assertions.
type spanRecorder struct{ spans []tracing.EndedSpan }

func (r *spanRecorder) Export(_ context.Context, span tracing.EndedSpan) {
	r.spans = append(r.spans, span)
}

func metricValue(t *testing.T, reg *metrics.Registry, name string) float64 {
	t.Helper()
	for _, s := range reg.Snapshot() {
		if s.Name == name {
			return s.Value
		}
	}
	t.Fatalf("no sample for %s in %+v", name, reg.Snapshot())
	return 0
}

// TestRelayRecordsJobDispatchSpanAndCorrelation: a delivered job opens a
// job.dispatch span whose trace id derives from the payload correlation id,
// and the handler context carries the same correlation id so its logs join.
func TestRelayRecordsJobDispatchSpanAndCorrelation(t *testing.T) {
	store := &fakeStore{events: []ClaimedEvent{
		{ID: "ev-1", Type: "signal.transitioned", Payload: []byte(`{"correlation_id":"corr-abc","type":"signal.transitioned"}`), Attempts: 1},
	}}
	relay := newRelay(t, store)
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	rec := &spanRecorder{}
	relay.SetObservability(reg, tracing.New(rec))

	var seenCorrelation string
	var spanName string
	if err := relay.Register("signal.transitioned", func(ctx context.Context, _ ClaimedEvent) error {
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
	if seenCorrelation != "corr-abc" {
		t.Fatalf("handler correlation id = %q, want the payload's corr-abc", seenCorrelation)
	}
	if spanName != "job.dispatch" {
		t.Fatalf("handler span = %q, want job.dispatch", spanName)
	}
	if len(rec.spans) != 1 {
		t.Fatalf("exported %d spans, want 1", len(rec.spans))
	}
	if want := tracing.TraceIDForCorrelation("corr-abc"); rec.spans[0].TraceID != want {
		t.Fatalf("span trace id = %q, want the correlation-derived %q", rec.spans[0].TraceID, want)
	}
	if got := metricValue(t, reg, metrics.NameJobsAttemptsTotal); got < 1 {
		t.Fatalf("jobs_attempts_total = %v, want >= 1", got)
	}
	if got := metricValue(t, reg, metrics.NameJobsQueueDepth); got != 1 {
		t.Fatalf("jobs_queue_depth = %v, want the claimed batch size 1", got)
	}
}

// TestRelayDeadLetterMetric: a permanently failed job advances the
// dead-letter counter.
func TestRelayDeadLetterMetric(t *testing.T) {
	store := &fakeStore{events: []ClaimedEvent{
		{ID: "ev-2", Type: "no.handler", Attempts: 1},
	}}
	relay := newRelay(t, store)
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	relay.SetObservability(reg, nil)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if got := metricValue(t, reg, metrics.NameJobsDeadLettersTotal); got != 1 {
		t.Fatalf("jobs_dead_letters_total = %v, want 1", got)
	}
}
