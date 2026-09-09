package worker

// Tests of the WP-3.08 matching job handlers (matching.go, DEV-064):
// the matching.rebuild and matching.recompute handlers decode their job
// payloads, drive the wired matching runs and map the outcomes onto the
// relay's delivery semantics — a delivered run is acked, an
// infrastructure failure of a run is a temporary failure that stays
// claimed (the expired lease redelivers it — the at-least-once crash/
// lease path of ch. 14.2, TR-012), and a malformed payload, an envelope
// mismatch or a validation/not-found outcome is permanent and
// dead-letters the job with the error text recorded. Registration on the
// type-keyed registry and the lease redelivery are exercised through the
// real relay (fakeStore/loopStore), so the tests cover dispatch, ack and
// dead-letter transitions without a database.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// scriptedMatchingRunner is a MatchingJobRunner whose outcomes the test
// fixes; it records the last inputs and call counts so the tests can
// assert what the handlers drove and how often a redelivered job ran.
type scriptedMatchingRunner struct {
	rebuildRes   application.RebuildMatchingResult
	rebuildErr   error
	recomputeRes application.RecomputeMatchingResult
	recomputeErr error

	rebuildInput   application.RebuildMatchingInput
	recomputeInput application.RecomputeMatchingInput
	rebuildCalls   int
	recomputeCalls int
}

func (r *scriptedMatchingRunner) RebuildMatching(_ context.Context, in application.RebuildMatchingInput) (application.RebuildMatchingResult, error) {
	r.rebuildCalls++
	r.rebuildInput = in
	return r.rebuildRes, r.rebuildErr
}

func (r *scriptedMatchingRunner) RecomputeMatching(_ context.Context, in application.RecomputeMatchingInput) (application.RecomputeMatchingResult, error) {
	r.recomputeCalls++
	r.recomputeInput = in
	return r.recomputeRes, r.recomputeErr
}

var _ MatchingJobRunner = (*scriptedMatchingRunner)(nil)

// matchingRelay wires a relay on a scripted store with both matching job
// handlers registered on the given runner.
func matchingRelay(t *testing.T, runner MatchingJobRunner, store OutboxStore) *Relay {
	t.Helper()
	relay := newRelay(t, store)
	jobs, err := NewMatchingJobs(runner, discardLogger())
	if err != nil {
		t.Fatalf("NewMatchingJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	return relay
}

// rebuildEvent renders one claimed matching.rebuild event whose payload
// mirrors what the DEV-060 inventory commit enqueues.
func rebuildEvent(id, ruleVersion, snapshot string) ClaimedEvent {
	payload, err := json.Marshal(application.MatchingRebuildPayload{
		EventID:           "evt-rebuild",
		Type:              application.EventTypeMatchingRebuild,
		ImportID:          "import-1",
		RuleVersion:       ruleVersion,
		InventorySnapshot: snapshot,
		OccurredAt:        time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		CorrelationID:     "corr-1",
	})
	if err != nil {
		panic(err)
	}
	return ClaimedEvent{ID: id, Type: application.EventTypeMatchingRebuild, Payload: payload}
}

// recomputeEvent renders one claimed matching.recompute event of a
// pre-filtered CVE batch.
func recomputeEvent(id string, vulnIDs []string, ruleVersion string) ClaimedEvent {
	payload, err := json.Marshal(application.MatchingRecomputePayload{
		EventID:          "evt-recompute",
		Type:             application.EventTypeMatchingRecompute,
		VulnerabilityIDs: vulnIDs,
		ComponentScope:   "acme/widget",
		RuleVersion:      ruleVersion,
		OccurredAt:       time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		CorrelationID:    "corr-2",
	})
	if err != nil {
		panic(err)
	}
	return ClaimedEvent{ID: id, Type: application.EventTypeMatchingRecompute, Payload: payload}
}

// TestMatchingRebuildHandlerDeliversAndAcks: the drain dispatches a
// matching.rebuild event to the registered handler, which decodes the
// payload the inventory commit enqueued, drives the rebuild run with the
// decoded rule version and inventory snapshot and reports delivery — the
// row is acked.
func TestMatchingRebuildHandlerDeliversAndAcks(t *testing.T) {
	runner := &scriptedMatchingRunner{}
	store := &fakeStore{events: []ClaimedEvent{rebuildEvent("job-1", "a0000000000d0000000000", "snap-1")}}
	relay := matchingRelay(t, runner, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 1 || store.acked[0] != "job-1" {
		t.Fatalf("acked = %v, want the rebuild job acked", store.acked)
	}
	if len(store.dead) != 0 {
		t.Fatalf("dead-lettered = %v, want none", store.dead)
	}
	if runner.rebuildCalls != 1 {
		t.Fatalf("rebuild runs = %d, want 1", runner.rebuildCalls)
	}
	if runner.rebuildInput.RuleVersion != "a0000000000d0000000000" || runner.rebuildInput.InventorySnapshot != "snap-1" {
		t.Fatalf("runner input = %+v, want the decoded rule_version and inventory_snapshot", runner.rebuildInput)
	}
}

// TestMatchingRecomputeHandlerDeliversAndAcks: the drain dispatches a
// matching.recompute event of a pre-filtered CVE batch; the handler
// decodes the batch and drives the recompute run with it.
func TestMatchingRecomputeHandlerDeliversAndAcks(t *testing.T) {
	runner := &scriptedMatchingRunner{}
	store := &fakeStore{events: []ClaimedEvent{recomputeEvent("job-2", []string{"v-1", "v-2"}, "a0000000000d0000000000")}}
	relay := matchingRelay(t, runner, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 1 || store.acked[0] != "job-2" {
		t.Fatalf("acked = %v, want the recompute job acked", store.acked)
	}
	if runner.recomputeCalls != 1 {
		t.Fatalf("recompute runs = %d, want 1", runner.recomputeCalls)
	}
	if len(runner.recomputeInput.VulnerabilityIDs) != 2 ||
		runner.recomputeInput.VulnerabilityIDs[0] != "v-1" || runner.recomputeInput.VulnerabilityIDs[1] != "v-2" ||
		runner.recomputeInput.ComponentScope != "acme/widget" ||
		runner.recomputeInput.RuleVersion != "a0000000000d0000000000" {
		t.Fatalf("runner input = %+v, want the decoded batch, scope and rule version", runner.recomputeInput)
	}
}

// TestMatchingHandlersDeadLetterPermanentOutcomes: a malformed payload,
// an envelope whose type mismatches the outbox type, a payload missing
// its job fields and a run reporting a validation outcome are permanent
// failures — the drain dead-letters the row with the error text recorded
// instead of retrying a job that can never succeed.
func TestMatchingHandlersDeadLetterPermanentOutcomes(t *testing.T) {
	ctx := context.Background()

	badPayload := ClaimedEvent{ID: "job-bad", Type: application.EventTypeMatchingRebuild, Payload: []byte(`{"event_id":`)}
	runner := &scriptedMatchingRunner{}
	store := &fakeStore{events: []ClaimedEvent{badPayload}}
	relay := matchingRelay(t, runner, store)
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (malformed payload): %v", err)
	}
	if len(store.dead) != 1 || store.dead[0].id != "job-bad" || !contains(store.dead[0].lastError, "decode job payload") {
		t.Fatalf("dead-letter = %v, want the malformed payload dead-lettered with the decode error", store.dead)
	}
	if runner.rebuildCalls != 0 {
		t.Fatalf("runner called %d times for a malformed payload, want 0", runner.rebuildCalls)
	}

	// Envelope mismatch: the payload of one job type routed under the
	// other's outbox type.
	wrongType := rebuildEvent("job-type", "a0000000000d0000000000", "snap-1")
	wrongType.Type = application.EventTypeMatchingRecompute
	store2 := &fakeStore{events: []ClaimedEvent{wrongType}}
	relay2 := matchingRelay(t, &scriptedMatchingRunner{}, store2)
	if err := relay2.Drain(ctx); err != nil {
		t.Fatalf("Drain (envelope mismatch): %v", err)
	}
	if len(store2.dead) != 1 || !contains(store2.dead[0].lastError, "does not match the outbox type") {
		t.Fatalf("dead-letter = %v, want the envelope mismatch dead-lettered", store2.dead)
	}

	// Missing job fields (no inventory snapshot).
	empty := rebuildEvent("job-empty", "a0000000000d0000000000", "")
	store3 := &fakeStore{events: []ClaimedEvent{empty}}
	relay3 := matchingRelay(t, &scriptedMatchingRunner{}, store3)
	if err := relay3.Drain(ctx); err != nil {
		t.Fatalf("Drain (missing fields): %v", err)
	}
	if len(store3.dead) != 1 {
		t.Fatalf("dead-letter = %v, want the field-less payload dead-lettered", store3.dead)
	}

	// A run reporting a validation outcome (the runner classifies the
	// job payload as invalid) is equally permanent.
	store4 := &fakeStore{events: []ClaimedEvent{rebuildEvent("job-val", "a0000000000d0000000000", "snap-1")}}
	valRunner := &scriptedMatchingRunner{rebuildErr: application.Validationf("matching_rebuild", "invalid job payload")}
	relay4 := matchingRelay(t, valRunner, store4)
	if err := relay4.Drain(ctx); err != nil {
		t.Fatalf("Drain (validation outcome): %v", err)
	}
	if len(store4.dead) != 1 || !contains(store4.dead[0].lastError, "validation") {
		t.Fatalf("dead-letter = %v, want the validation outcome dead-lettered", store4.dead)
	}
}

// TestMatchingHandlersRetryInfrastructureFailures: an infrastructure
// failure of a run (database trouble) is a temporary delivery failure —
// the drain leaves the row claimed, never dead-lettered, and the expired
// lease makes the next claim redeliver it (at-least-once, ch. 14.2).
func TestMatchingHandlersRetryInfrastructureFailures(t *testing.T) {
	ctx := context.Background()

	// Direct handler check: the classified error is a Retry (temporary).
	jobs, err := NewMatchingJobs(&scriptedMatchingRunner{rebuildErr: application.InfraError("matching_rebuild", errors.New("db down"))}, discardLogger())
	if err != nil {
		t.Fatalf("NewMatchingJobs: %v", err)
	}
	err = jobs.handleRebuild(ctx, rebuildEvent("job-1", "a0000000000d0000000000", "snap-1"))
	if err == nil || !isRetryable(err) {
		t.Fatalf("handler error = %v, want a retryable (temporary) failure", err)
	}

	// Drain level: an infra outcome leaves the row claimed — neither
	// acked nor dead-lettered.
	runner := &scriptedMatchingRunner{rebuildErr: application.InfraError("matching_rebuild", errors.New("db down"))}
	store := &fakeStore{events: []ClaimedEvent{rebuildEvent("job-1", "a0000000000d0000000000", "snap-1")}}
	relay := matchingRelay(t, runner, store)
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (infra failure): %v", err)
	}
	if len(store.acked) != 0 || len(store.dead) != 0 {
		t.Fatalf("acked = %v dead-lettered = %v, want the row left claimed for redelivery", store.acked, store.dead)
	}
}

// TestMatchingJobLeaseRedeliveryReRunsTheJob is the crash/lease path of
// the matching jobs (TR-012, ch. 14.2): a matching.rebuild run that
// failed with an infrastructure error leaves the row claimed; after the
// lease expires the next drain re-claims and re-runs the job — the same
// payload, delivered again — and the row reaches done. The re-run is a
// no-op at the data level through the idempotent match insert (proven at
// the run level in the application tests); here the relay mechanics of
// the redelivery are exercised end-to-end over the lease-based loop
// store.
func TestMatchingJobLeaseRedeliveryReRunsTheJob(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	clk := clock.NewFakeClock(start)

	db := &jobDB{}
	store := newLoopStore(db, clk)
	relay := newRelay(t, store)

	// The matching.rebuild row the inventory commit would enqueue (the
	// dedupe key of DEV-060: rule_version + inventory_snapshot).
	snapshot := "snap-1"
	db.outbox = append(db.outbox, application.OutboxEvent{
		Type:        application.EventTypeMatchingRebuild,
		Payload:     rebuildEvent("job-1", "a0000000000d0000000000", snapshot).Payload,
		DedupeKey:   application.MatchingRebuildDedupeKey("a0000000000d0000000000", snapshot),
		AvailableAt: start,
		CreatedAt:   start,
	})

	// The run fails on the first delivery (the crash: the lease expires
	// with the row claimed) and succeeds on the redelivery.
	runner := &scriptedMatchingRunner{rebuildErr: application.InfraError("matching_rebuild", errors.New("db down"))}
	jobs, err := NewMatchingJobs(runner, discardLogger())
	if err != nil {
		t.Fatalf("NewMatchingJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}

	// Drain 1: the infra failure leaves the job claimed (attempt 1).
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (first delivery): %v", err)
	}
	st := store.stateOf(db.outbox[0].DedupeKey)
	if st.status != "claimed" || st.attempts != 1 {
		t.Fatalf("job state after the failed delivery = %+v, want claimed (attempt 1)", st)
	}

	// The lease expires; drain 2 re-claims and re-runs the job with the
	// identical payload — the store recovered, the delivery succeeds.
	runner.rebuildErr = nil
	clk.Advance(61 * time.Second)
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("Drain (redelivery): %v", err)
	}
	st = store.stateOf(db.outbox[0].DedupeKey)
	if st.status != "done" || st.attempts != 2 {
		t.Fatalf("job state after the redelivery = %+v, want done on the second attempt", st)
	}
	if runner.rebuildCalls != 2 {
		t.Fatalf("rebuild runs = %d, want 2 (the re-claimed job re-runs)", runner.rebuildCalls)
	}
	if runner.rebuildInput.RuleVersion != "a0000000000d0000000000" || runner.rebuildInput.InventorySnapshot != snapshot {
		t.Fatalf("redelivered runner input = %+v, want the identical job payload", runner.rebuildInput)
	}
}

// TestNewMatchingJobsRejectsWiringErrors: a nil runner is a wiring error
// and registering a matching handler over an already-bound type fails.
func TestNewMatchingJobsRejectsWiringErrors(t *testing.T) {
	if jobs, err := NewMatchingJobs(nil, discardLogger()); err == nil || jobs != nil {
		t.Fatalf("NewMatchingJobs(nil) = %v/%v, want a wiring error", jobs, err)
	}
	relay := newRelay(t, &fakeStore{})
	jobs, err := NewMatchingJobs(&scriptedMatchingRunner{}, discardLogger())
	if err != nil {
		t.Fatalf("NewMatchingJobs: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	if err := jobs.RegisterHandlers(relay); err == nil {
		t.Fatal("RegisterHandlers over the already-bound types succeeded, want an error")
	}
}

// contains reports whether s contains the substring.
func contains(s, substr string) bool { return strings.Contains(s, substr) }
