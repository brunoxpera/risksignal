package worker

// Unit tests of the WP-2.08 source job handlers (ARCH-002 §5, source.go)
// with scripted fakes: the source.fetch and source.normalize handlers
// resolve the job's source adapter through the type-keyed registry, drive
// the wired use cases and map the outcomes onto the relay's delivery
// semantics — a delivered fetch or a no-change full set is acked, a
// rate-limited fetch is a temporary failure that stays claimable (never
// dead-lettered as a source fault, ch. 14.2), an infrastructure failure is
// retried after the lease expires, and a permanent outcome (unknown
// source, missing adapter, malformed payload, validation/not-found error)
// dead-letters the job with the error text recorded. The persistence
// behind the use cases is irrelevant here — the runner is scripted — so
// the relay semantics are exercised without a database.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
)

// stubSource implements application.SourcePort for the registry entries of
// these tests: only Type() is ever read by the handlers (the adapter is
// handed through to the runner unchanged); the other methods fail loudly
// when a test drives them accidentally.
type stubSource struct{ typ application.SourceType }

func (s *stubSource) Type() application.SourceType { return s.typ }
func (s *stubSource) Plan() application.SourcePlan { return application.SourcePlan{} }
func (s *stubSource) NormalizerVersion() string    { return "test-normalizer-v1" }
func (s *stubSource) Fetch(ctx context.Context, in application.FetchInput) (application.FetchOutput, error) {
	return application.FetchOutput{}, errors.New("stub: unexpected Fetch")
}
func (s *stubSource) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	return application.NormalizeResult{}, errors.New("stub: unexpected Normalize")
}

var _ application.SourcePort = (*stubSource)(nil)

// scriptedRunner is a SourceJobRunner whose outcomes the test fixes; it
// records the last inputs so the tests can assert what the handlers drove.
type scriptedRunner struct {
	fetchRes application.FetchSourceResult
	fetchErr error
	normRes  application.NormalizeSourceResult
	normErr  error

	fetchInput application.FetchSourceInput
	normInput  application.NormalizeSourceInput
	fetchCalls int
	normCalls  int
}

func (r *scriptedRunner) FetchSource(ctx context.Context, in application.FetchSourceInput) (application.FetchSourceResult, error) {
	r.fetchCalls++
	r.fetchInput = in
	return r.fetchRes, r.fetchErr
}

func (r *scriptedRunner) NormalizeSource(ctx context.Context, in application.NormalizeSourceInput) (application.NormalizeSourceResult, error) {
	r.normCalls++
	r.normInput = in
	return r.normRes, r.normErr
}

var _ SourceJobRunner = (*scriptedRunner)(nil)

// mapResolver is a SourceResolver over a fixed id -> descriptor map.
type mapResolver struct {
	sources map[string]application.SourceDescriptor
}

func (r *mapResolver) GetByID(ctx context.Context, id string) (application.SourceDescriptor, error) {
	desc, ok := r.sources[id]
	if !ok {
		return application.SourceDescriptor{}, application.NotFoundError("source.get_by_id", errors.New("no such source"))
	}
	return desc, nil
}

var _ SourceResolver = (*mapResolver)(nil)

// newJobHarness wires a relay with the two source job handlers registered
// on a scripted runner, a resolver and an adapter registry. The handlers
// run without a metrics registry (the run-loop metrics tests construct
// SourceJobs directly with one).
func newJobHarness(t *testing.T, runner SourceJobRunner, resolver SourceResolver, adapters map[application.SourceType]application.SourcePort) (*Relay, *fakeStore, *scriptedRunner) {
	t.Helper()
	store := &fakeStore{}
	relay := newRelay(t, store)
	jobs, err := NewSourceJobs(runner, resolver, adapters, nil, discardLogger())
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	scripted, _ := runner.(*scriptedRunner)
	return relay, store, scripted
}

// fetchEvent builds one claimed source.fetch event for source src with the
// given plan time (or request id when request is set).
func fetchEvent(id, src string, plan time.Time, request string) ClaimedEvent {
	payload := application.SourceFetchJobPayload{SourceID: src, PlanTime: plan, RequestID: request}
	body, _ := json.Marshal(payload)
	return ClaimedEvent{ID: id, Type: application.EventTypeSourceFetch, Payload: body, Attempts: 1}
}

// kevRegistry is the registry of the fetch/normalize tests.
var kevRegistry = map[application.SourceType]application.SourcePort{
	application.SourceTypeKEV: &stubSource{typ: application.SourceTypeKEV},
}

// kevResolver resolves one kev source row.
func kevResolver() *mapResolver {
	return &mapResolver{sources: map[string]application.SourceDescriptor{
		"src-kev": {ID: "src-kev", Type: application.SourceTypeKEV},
	}}
}

// TestFetchHandlerAcksDeliveredFetch: a source.fetch job whose fetch stored
// a raw record is delivered — the runner received the source id and the
// adapter the source's type resolves to, and the relay acks the row.
func TestFetchHandlerAcksDeliveredFetch(t *testing.T) {
	runner := &scriptedRunner{fetchRes: application.FetchSourceResult{
		RunID: "run-1", RawRecordID: "raw-1", Status: application.SourceRunStatusSucceeded,
	}}
	relay, store, scripted := newJobHarness(t, runner, kevResolver(), kevRegistry)
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store.events = []ClaimedEvent{fetchEvent("evt-1", "src-kev", now, "")}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 1 || store.acked[0] != "evt-1" {
		t.Fatalf("acked = %v, want the fetch event", store.acked)
	}
	if len(store.dead) != 0 {
		t.Fatalf("dead-lettered = %+v, want none", store.dead)
	}
	if scripted.fetchCalls != 1 || scripted.fetchInput.SourceID != "src-kev" {
		t.Fatalf("FetchSource input = %+v, want the source id", scripted.fetchInput)
	}
	if got := scripted.fetchInput.Adapter.Type(); got != application.SourceTypeKEV {
		t.Fatalf("adapter type = %q, want the kev adapter of the registry", got)
	}
}

// TestFetchHandlerAcksNoChangeRun: an unchanged full set (ch. 8.3) is a
// successful no-op run and the job is delivered — nothing to normalize.
func TestFetchHandlerAcksNoChangeRun(t *testing.T) {
	runner := &scriptedRunner{fetchRes: application.FetchSourceResult{
		RunID: "run-1", Status: application.SourceRunStatusSucceeded, Meta: application.FetchMeta{NoChange: true},
	}}
	relay, store, _ := newJobHarness(t, runner, kevResolver(), kevRegistry)
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store.events = []ClaimedEvent{fetchEvent("evt-1", "src-kev", now, "")}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 1 || len(store.dead) != 0 {
		t.Fatalf("acked = %v, dead-lettered = %+v; want the no-change run delivered", store.acked, store.dead)
	}
}

// TestFetchHandlerRateLimitedStaysClaimable is the required rate-limit
// semantics (ch. 14.2, ARCH-002 §5): a rate-limited fetch is recorded on
// the run as rate-limited (never a source technical error) and the handler
// reports it as a temporary failure — the relay leaves the job claimed,
// neither acked nor dead-lettered, so the expired lease redelivers it.
func TestFetchHandlerRateLimitedStaysClaimable(t *testing.T) {
	runner := &scriptedRunner{fetchRes: application.FetchSourceResult{
		RunID: "run-1", Status: application.SourceRunStatusFailed, Meta: application.FetchMeta{RateLimited: true, RetryAfter: 90},
	}}
	relay, store, _ := newJobHarness(t, runner, kevResolver(), kevRegistry)
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	store.events = []ClaimedEvent{fetchEvent("evt-1", "src-kev", now, "")}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 0 || len(store.dead) != 0 {
		t.Fatalf("acked = %v, dead-lettered = %+v; want the job left claimed for the lease-expiry redelivery", store.acked, store.dead)
	}
}

// TestFetchHandlerRetriesInfrastructureFailures: an infrastructure failure
// of the fetch half (upstream unreachable, database trouble) is temporary —
// the job stays claimable. On the last allowed attempt the relay's ch. 14.2
// attempt cap still dead-letters it (generic cap semantics of relay.go).
func TestFetchHandlerRetriesInfrastructureFailures(t *testing.T) {
	cause := application.InfraError("fetch_source", errors.New("dial tcp: connection refused"))

	t.Run("below the attempt cap the job stays claimable", func(t *testing.T) {
		runner := &scriptedRunner{fetchErr: cause}
		relay, store, _ := newJobHarness(t, runner, kevResolver(), kevRegistry)
		now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
		store.events = []ClaimedEvent{fetchEvent("evt-1", "src-kev", now, "")}
		if err := relay.Drain(context.Background()); err != nil {
			t.Fatalf("Drain: %v", err)
		}
		if len(store.acked) != 0 || len(store.dead) != 0 {
			t.Fatalf("acked = %v, dead-lettered = %+v; want the infra failure retried", store.acked, store.dead)
		}
	})

	t.Run("past the attempt cap the job is dead-lettered", func(t *testing.T) {
		runner := &scriptedRunner{fetchErr: cause}
		relay, store, _ := newJobHarness(t, runner, kevResolver(), kevRegistry)
		now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
		event := fetchEvent("evt-1", "src-kev", now, "")
		event.Attempts = maxAttempts
		store.events = []ClaimedEvent{event}
		if err := relay.Drain(context.Background()); err != nil {
			t.Fatalf("Drain: %v", err)
		}
		if len(store.acked) != 0 || len(store.dead) != 1 {
			t.Fatalf("acked = %v, dead-lettered = %+v; want the capped job dead-lettered", store.acked, store.dead)
		}
	})
}

// TestFetchHandlerDeadLettersPermanentOutcomes: a validation error of the
// use case (source/adapter mismatch, malformed cursor), an unknown source
// row, a source type without a registered adapter and a malformed job
// payload are all permanent — the job is dead-lettered with the error text
// recorded, never retried.
func TestFetchHandlerDeadLettersPermanentOutcomes(t *testing.T) {
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		runner   *scriptedRunner
		resolver SourceResolver
		registry map[application.SourceType]application.SourcePort
		event    ClaimedEvent
	}{
		{
			name:     "validation error",
			runner:   &scriptedRunner{fetchErr: application.Validationf("fetch_source", "adapter type mismatch")},
			resolver: kevResolver(),
			registry: kevRegistry,
			event:    fetchEvent("evt-1", "src-kev", now, ""),
		},
		{
			name:     "unknown source",
			runner:   &scriptedRunner{},
			resolver: &mapResolver{sources: map[string]application.SourceDescriptor{}},
			registry: kevRegistry,
			event:    fetchEvent("evt-1", "no-such-source", now, ""),
		},
		{
			name:     "source type without a registered adapter",
			runner:   &scriptedRunner{},
			resolver: &mapResolver{sources: map[string]application.SourceDescriptor{"src-syn": {ID: "src-syn", Type: application.SourceTypeSynthetic}}},
			registry: kevRegistry,
			event:    fetchEvent("evt-1", "src-syn", now, ""),
		},
		{
			name:     "malformed payload",
			runner:   &scriptedRunner{},
			resolver: kevResolver(),
			registry: kevRegistry,
			event:    ClaimedEvent{ID: "evt-1", Type: application.EventTypeSourceFetch, Payload: []byte("not json"), Attempts: 1},
		},
		{
			name:     "payload without a source id",
			runner:   &scriptedRunner{},
			resolver: kevResolver(),
			registry: kevRegistry,
			event: ClaimedEvent{
				ID: "evt-1", Type: application.EventTypeSourceFetch,
				Payload: []byte(`{"plan_time":"2026-09-09T00:00:00Z"}`), Attempts: 1,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay, store, _ := newJobHarness(t, tc.runner, tc.resolver, tc.registry)
			store.events = []ClaimedEvent{tc.event}
			if err := relay.Drain(context.Background()); err != nil {
				t.Fatalf("Drain: %v", err)
			}
			if len(store.acked) != 0 || len(store.dead) != 1 {
				t.Fatalf("acked = %v, dead-lettered = %+v; want the permanent failure dead-lettered", store.acked, store.dead)
			}
			if store.dead[0].id != tc.event.ID || store.dead[0].lastError == "" {
				t.Fatalf("dead-letter record = %+v, want the event id and the recorded error text", store.dead[0])
			}
		})
	}
}

// TestNormalizeHandlerAcksDeliveredPass: a source.normalize job whose pass
// succeeded (isolated per-record errors included — they never fail the run,
// ch. 8.1 step 5) is delivered and acked; the runner received the raw
// record id and the source's adapter.
func TestNormalizeHandlerAcksDeliveredPass(t *testing.T) {
	runner := &scriptedRunner{normRes: application.NormalizeSourceResult{
		RunID:    "run-1",
		Status:   application.SourceRunStatusSucceeded,
		Counters: application.SourceRunCounters{Records: 1, Errors: 2, Quarantined: 2},
	}}
	relay, store, scripted := newJobHarness(t, runner, kevResolver(), kevRegistry)
	body, _ := json.Marshal(application.SourceNormalizeJobPayload{RawRecordID: "raw-1", SourceID: "src-kev", FetchedAt: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)})
	store.events = []ClaimedEvent{{ID: "evt-1", Type: application.EventTypeSourceNormalize, Payload: body, Attempts: 1}}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 1 || len(store.dead) != 0 {
		t.Fatalf("acked = %v, dead-lettered = %+v; want the normalize job delivered", store.acked, store.dead)
	}
	if scripted.normCalls != 1 || scripted.normInput.RawRecordID != "raw-1" {
		t.Fatalf("NormalizeSource input = %+v, want the raw record id", scripted.normInput)
	}
	if got := scripted.normInput.Adapter.Type(); got != application.SourceTypeKEV {
		t.Fatalf("adapter type = %q, want the kev adapter of the registry", got)
	}
}

// TestNormalizeHandlerClassifiesFailures: an infrastructure failure of the
// pass (a failing sink write) is retried — the job stays claimable — while
// a missing raw record or source row is permanent and dead-letters.
func TestNormalizeHandlerClassifiesFailures(t *testing.T) {
	body, _ := json.Marshal(application.SourceNormalizeJobPayload{RawRecordID: "raw-1", SourceID: "src-kev"})

	t.Run("infrastructure failure stays claimable", func(t *testing.T) {
		runner := &scriptedRunner{normErr: application.InfraError("normalize_source", errors.New("sink write failed"))}
		relay, store, _ := newJobHarness(t, runner, kevResolver(), kevRegistry)
		store.events = []ClaimedEvent{{ID: "evt-1", Type: application.EventTypeSourceNormalize, Payload: body, Attempts: 1}}
		if err := relay.Drain(context.Background()); err != nil {
			t.Fatalf("Drain: %v", err)
		}
		if len(store.acked) != 0 || len(store.dead) != 0 {
			t.Fatalf("acked = %v, dead-lettered = %+v; want the infra failure retried", store.acked, store.dead)
		}
	})

	t.Run("missing raw record dead-letters", func(t *testing.T) {
		runner := &scriptedRunner{normErr: application.NotFoundError("normalize_source", errors.New("raw record not found"))}
		relay, store, _ := newJobHarness(t, runner, kevResolver(), kevRegistry)
		store.events = []ClaimedEvent{{ID: "evt-1", Type: application.EventTypeSourceNormalize, Payload: body, Attempts: 1}}
		if err := relay.Drain(context.Background()); err != nil {
			t.Fatalf("Drain: %v", err)
		}
		if len(store.acked) != 0 || len(store.dead) != 1 {
			t.Fatalf("acked = %v, dead-lettered = %+v; want the not-found job dead-lettered", store.acked, store.dead)
		}
	})
}

// TestNewSourceJobsRejectsWiringErrors: nil runner, resolver or registry
// are wiring errors reported at construction; RegisterHandlers rejects a
// relay that already carries one of the two job types.
func TestNewSourceJobsRejectsWiringErrors(t *testing.T) {
	if _, err := NewSourceJobs(nil, kevResolver(), kevRegistry, nil, nil); err == nil {
		t.Fatal("NewSourceJobs with a nil runner succeeded, want an error")
	}
	if _, err := NewSourceJobs(&scriptedRunner{}, nil, kevRegistry, nil, nil); err == nil {
		t.Fatal("NewSourceJobs with a nil resolver succeeded, want an error")
	}
	if _, err := NewSourceJobs(&scriptedRunner{}, kevResolver(), nil, nil, nil); err == nil {
		t.Fatal("NewSourceJobs with a nil registry succeeded, want an error")
	}

	relay := newRelay(t, &fakeStore{})
	if err := relay.Register(application.EventTypeSourceFetch, func(ctx context.Context, event ClaimedEvent) error { return nil }); err != nil {
		t.Fatalf("pre-register: %v", err)
	}
	jobs, err := NewSourceJobs(&scriptedRunner{}, kevResolver(), kevRegistry, nil, nil)
	if err != nil {
		t.Fatalf("NewSourceJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err == nil {
		t.Fatal("RegisterHandlers over an already-registered source.fetch type succeeded, want an error")
	}
}
