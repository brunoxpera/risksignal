package worker

// Tests of the WP-4.05 priority.recompute job handler (priority.go,
// ARCH-004 §5): the handler decodes the fan-in payload, drives the wired
// recompute use case and maps the outcome onto the relay's delivery
// semantics — a delivered recompute is acked, an infrastructure failure is a
// temporary failure that stays claimed (the expired lease redelivers it), and
// a malformed payload, an envelope mismatch or a validation/not-found outcome
// is permanent and dead-letters the job. Registration is exercised through the
// real relay (fakeStore), so dispatch, ack and dead-letter transitions are
// covered without a database.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// scriptedPriorityRunner is a PriorityRecomputeRunner whose outcome the test
// fixes; it records the last input and the call count.
type scriptedPriorityRunner struct {
	res  application.RecomputePriorityResult
	err  error
	in   application.RecomputePriorityInput
	runs int
}

func (r *scriptedPriorityRunner) RecomputePriority(_ context.Context, in application.RecomputePriorityInput) (application.RecomputePriorityResult, error) {
	r.runs++
	r.in = in
	return r.res, r.err
}

var _ PriorityRecomputeRunner = (*scriptedPriorityRunner)(nil)

// priorityRecomputeEvent renders one claimed priority.recompute event whose
// payload mirrors what the ARCH-004 §5 fan-in enqueues.
func priorityRecomputeEvent(id string) ClaimedEvent {
	payload, err := json.Marshal(application.PriorityRecomputePayload{
		EventID:       "evt-priority",
		Type:          application.EventTypePriorityRecompute,
		SignalID:      "sig-1",
		RuleVersion:   "p0000000001",
		InputHash:     "hash-1",
		OccurredAt:    time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		CorrelationID: "corr-1",
	})
	if err != nil {
		panic(err)
	}
	return ClaimedEvent{ID: id, Type: application.EventTypePriorityRecompute, Payload: payload}
}

// priorityRelay wires a relay on a scripted store with the priority.recompute
// handler registered on the given runner.
func priorityRelay(t *testing.T, runner PriorityRecomputeRunner, store OutboxStore) *Relay {
	t.Helper()
	relay := newRelay(t, store)
	jobs, err := NewPriorityRecomputeJobs(runner, discardLogger())
	if err != nil {
		t.Fatalf("NewPriorityRecomputeJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	return relay
}

// TestPriorityRecomputeHandlerDeliversAndAcks: the drain dispatches a
// priority.recompute event to the registered handler, which decodes the
// payload, drives the recompute for the payload signal and reports delivery —
// the row is acked.
func TestPriorityRecomputeHandlerDeliversAndAcks(t *testing.T) {
	runner := &scriptedPriorityRunner{res: application.RecomputePriorityResult{
		SignalID: "sig-1", Priority: domain.PriorityP3, RuleVersion: "p0000000001", InputHash: "hash-fresh", Changed: true,
	}}
	store := &fakeStore{events: []ClaimedEvent{priorityRecomputeEvent("job-1")}}
	relay := priorityRelay(t, runner, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 1 || store.acked[0] != "job-1" {
		t.Fatalf("acked = %v, want the recompute job acked", store.acked)
	}
	if len(store.dead) != 0 {
		t.Fatalf("dead-lettered = %v, want none", store.dead)
	}
	if runner.runs != 1 {
		t.Fatalf("recompute runs = %d, want 1", runner.runs)
	}
	if runner.in.SignalID != "sig-1" || runner.in.CorrelationID != "corr-1" {
		t.Fatalf("runner input = %+v, want the decoded signal_id and correlation_id", runner.in)
	}
	if runner.in.Actor.Type != application.ActorTypeSystem || runner.in.Actor.ID != application.ActorPriorityRecompute {
		t.Fatalf("runner actor = %+v, want the priority-recompute system principal", runner.in.Actor)
	}
}

// TestPriorityRecomputeHandlerDeadLettersPermanentOutcomes: a malformed
// payload, an envelope whose type mismatches the outbox type, a payload
// missing its job fields and a run reporting a validation outcome are
// permanent failures — the drain dead-letters the row with the error text
// recorded instead of retrying a job that can never succeed.
func TestPriorityRecomputeHandlerDeadLettersPermanentOutcomes(t *testing.T) {
	ctx := context.Background()

	bad := ClaimedEvent{ID: "job-bad", Type: application.EventTypePriorityRecompute, Payload: []byte(`{"event_id":`)}
	store := &fakeStore{events: []ClaimedEvent{bad}}
	relay := priorityRelay(t, &scriptedPriorityRunner{}, store)
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (malformed payload): %v", err)
	}
	if len(store.dead) != 1 || !contains(store.dead[0].lastError, "decode job payload") {
		t.Fatalf("dead-letter = %v, want the malformed payload dead-lettered", store.dead)
	}

	wrongType := priorityRecomputeEvent("job-type")
	// The outbox type stays priority.recompute (so the handler is dispatched)
	// while the payload's own type field names another job — the envelope
	// mismatch the handler must reject.
	wrongType.Payload = []byte(`{"event_id":"e","type":"matching.rebuild","signal_id":"sig-1","rule_version":"p0000000001"}`)
	store2 := &fakeStore{events: []ClaimedEvent{wrongType}}
	relay2 := priorityRelay(t, &scriptedPriorityRunner{}, store2)
	if err := relay2.Drain(ctx); err != nil {
		t.Fatalf("Drain (envelope mismatch): %v", err)
	}
	if len(store2.dead) != 1 || !contains(store2.dead[0].lastError, "does not match the outbox type") {
		t.Fatalf("dead-letter = %v, want the envelope mismatch dead-lettered", store2.dead)
	}

	// Field-less payload (no signal_id).
	empty := priorityRecomputeEvent("job-empty")
	empty.Payload = []byte(`{"event_id":"e","type":"priority.recompute","rule_version":"p0000000001"}`)
	store3 := &fakeStore{events: []ClaimedEvent{empty}}
	relay3 := priorityRelay(t, &scriptedPriorityRunner{}, store3)
	if err := relay3.Drain(ctx); err != nil {
		t.Fatalf("Drain (missing fields): %v", err)
	}
	if len(store3.dead) != 1 {
		t.Fatalf("dead-letter = %v, want the field-less payload dead-lettered", store3.dead)
	}

	// A run reporting a validation outcome is equally permanent.
	store4 := &fakeStore{events: []ClaimedEvent{priorityRecomputeEvent("job-val")}}
	relay4 := priorityRelay(t, &scriptedPriorityRunner{err: application.Validationf("recompute_priority", "bad factor set")}, store4)
	if err := relay4.Drain(ctx); err != nil {
		t.Fatalf("Drain (validation outcome): %v", err)
	}
	if len(store4.dead) != 1 || !contains(store4.dead[0].lastError, "validation") {
		t.Fatalf("dead-letter = %v, want the validation outcome dead-lettered", store4.dead)
	}
}

// TestPriorityRecomputeHandlerRetriesInfrastructureFailures: an
// infrastructure failure of the recompute is a temporary delivery failure —
// the drain leaves the row claimed, never dead-lettered, so the expired lease
// redelivers it (at-least-once, ch. 14.2).
func TestPriorityRecomputeHandlerRetriesInfrastructureFailures(t *testing.T) {
	runner := &scriptedPriorityRunner{err: application.InfraError("recompute_priority", errors.New("db down"))}
	store := &fakeStore{events: []ClaimedEvent{priorityRecomputeEvent("job-1")}}
	relay := priorityRelay(t, runner, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain (infra failure): %v", err)
	}
	if len(store.acked) != 0 || len(store.dead) != 0 {
		t.Fatalf("acked = %v dead-lettered = %v, want the row left claimed for redelivery", store.acked, store.dead)
	}
}

// TestNewPriorityRecomputeJobsRejectsWiringErrors: a nil runner is a wiring
// error and registering the handler over an already-bound type fails.
func TestNewPriorityRecomputeJobsRejectsWiringErrors(t *testing.T) {
	if jobs, err := NewPriorityRecomputeJobs(nil, discardLogger()); err == nil || jobs != nil {
		t.Fatalf("NewPriorityRecomputeJobs(nil) = %v/%v, want a wiring error", jobs, err)
	}
	relay := newRelay(t, &fakeStore{})
	jobs, err := NewPriorityRecomputeJobs(&scriptedPriorityRunner{}, discardLogger())
	if err != nil {
		t.Fatalf("NewPriorityRecomputeJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err == nil {
		t.Fatal("RegisterHandlers over the already-bound type succeeded, want an error")
	}
}
