package worker

// Unit tests of the WP-1b.06 outbox relay (relay.go): the drain claims the
// bounded batch, dispatches every event to the handler registered for its
// type and applies the ARCH-001 §2 terminal transition per outcome —
// delivered events are acked, unregistered types and permanent failures are
// dead-lettered with the error recorded, temporary failures (Retry) below
// the ch. 14.2 attempt cap are left claimed for the lease-expiry
// redelivery, and a temporary failure past the cap is dead-lettered. The
// store is a fake (the SQL side is covered by the integration test in
// cmd/risksignal-worker), so the relay semantics are exercised without a
// database.

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// fakeStore is an in-memory worker.OutboxStore: ClaimBatch returns the
// scripted events, Ack and DeadLetter record their calls so the tests can
// assert exactly which terminal transition the relay applied to which row.
type fakeStore struct {
	events   []ClaimedEvent
	claimErr error
	ackErr   error
	deadErr  error
	limit    int
	acked    []string
	dead     []deadLetterCall
}

// deadLetterCall is one recorded DeadLetter invocation.
type deadLetterCall struct {
	id        string
	lastError string
}

func (f *fakeStore) ClaimBatch(ctx context.Context, limit int) ([]ClaimedEvent, error) {
	f.limit = limit
	return f.events, f.claimErr
}

func (f *fakeStore) Ack(ctx context.Context, id string) error {
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked = append(f.acked, id)
	return nil
}

func (f *fakeStore) DeadLetter(ctx context.Context, id, lastError string) error {
	if f.deadErr != nil {
		return f.deadErr
	}
	f.dead = append(f.dead, deadLetterCall{id: id, lastError: lastError})
	return nil
}

// newRelay builds a relay on store with a silent logger.
func newRelay(t *testing.T, store OutboxStore) *Relay {
	t.Helper()
	relay, err := NewRelay(store, discardLogger())
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	return relay
}

// TestRelayDrainClaimsBoundedBatchAndAcksDeliveredEvents: every claimed
// event whose handler succeeds is delivered — acked in claim order with the
// exact payload handed over — and the drain claims the ARCH-001 §2 bounded
// batch size.
func TestRelayDrainClaimsBoundedBatchAndAcksDeliveredEvents(t *testing.T) {
	store := &fakeStore{
		events: []ClaimedEvent{
			{ID: "11111111-1111-1111-1111-111111111111", Type: "signal.created", Payload: []byte(`{"priority":"P1"}`), Attempts: 1},
			{ID: "22222222-2222-2222-2222-222222222222", Type: "signal.created", Payload: []byte(`{"priority":"P2"}`), Attempts: 1},
		},
	}
	relay := newRelay(t, store)

	var handled []ClaimedEvent
	handler := func(ctx context.Context, event ClaimedEvent) error {
		handled = append(handled, event)
		return nil
	}
	if err := relay.Register("signal.created", handler); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if store.limit != claimBatchSize {
		t.Fatalf("claim batch limit = %d, want the bounded batch %d", store.limit, claimBatchSize)
	}
	if !reflect.DeepEqual(store.acked, []string{store.events[0].ID, store.events[1].ID}) {
		t.Fatalf("acked ids = %v, want both events in claim order", store.acked)
	}
	if len(store.dead) != 0 {
		t.Fatalf("dead-lettered = %+v, want none", store.dead)
	}
	if !reflect.DeepEqual(handled, store.events) {
		t.Fatalf("handler received %+v, want the claimed events with payloads intact", handled)
	}
}

// TestRelayDrainDeadLettersUnregisteredType: a claimed event whose type has
// no registered handler must not crash the drain — the row is dead-lettered
// with a clear last_error naming the type.
func TestRelayDrainDeadLettersUnregisteredType(t *testing.T) {
	store := &fakeStore{events: []ClaimedEvent{
		{ID: "33333333-3333-3333-3333-333333333333", Type: "i2.unknown.job", Attempts: 1},
	}}
	relay := newRelay(t, store)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain returned %v, want nil (unknown type must not fail the drain)", err)
	}
	if len(store.acked) != 0 {
		t.Fatalf("acked = %v, want none", store.acked)
	}
	if len(store.dead) != 1 || store.dead[0].id != store.events[0].ID {
		t.Fatalf("dead-lettered = %+v, want the unregistered event", store.dead)
	}
	if store.dead[0].lastError != `no handler registered for outbox type "i2.unknown.job"` {
		t.Fatalf("last_error = %q, want a clear message naming the type", store.dead[0].lastError)
	}
}

// TestRelayDrainLeavesTemporaryFailuresForRedelivery: a Retry-marked
// failure below the attempt cap leaves the row claimed — neither acked nor
// dead-lettered — so the expired lease makes the next claim redeliver it
// (at-least-once, ARCH-001 §2).
func TestRelayDrainLeavesTemporaryFailuresForRedelivery(t *testing.T) {
	store := &fakeStore{events: []ClaimedEvent{
		{ID: "44444444-4444-4444-4444-444444444444", Type: "signal.created", Attempts: maxAttempts - 1},
	}}
	relay := newRelay(t, store)
	if err := relay.Register("signal.created", func(ctx context.Context, event ClaimedEvent) error {
		return Retry(errors.New("notification backend busy"))
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 0 || len(store.dead) != 0 {
		t.Fatalf("acked = %v, dead-lettered = %+v; want the row left claimed", store.acked, store.dead)
	}
}

// TestRelayDrainDeadLettersTemporaryFailurePastAttemptCap: a Retry-marked
// failure on the last allowed attempt is dead-lettered instead of being
// redelivered forever (ch. 14.2 attempt cap), with the failure recorded.
func TestRelayDrainDeadLettersTemporaryFailurePastAttemptCap(t *testing.T) {
	store := &fakeStore{events: []ClaimedEvent{
		{ID: "55555555-5555-5555-5555-555555555555", Type: "signal.created", Attempts: maxAttempts},
	}}
	relay := newRelay(t, store)
	cause := errors.New("notification backend busy")
	if err := relay.Register("signal.created", func(ctx context.Context, event ClaimedEvent) error {
		return Retry(cause)
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 0 {
		t.Fatalf("acked = %v, want none", store.acked)
	}
	if len(store.dead) != 1 || store.dead[0].id != store.events[0].ID {
		t.Fatalf("dead-lettered = %+v, want the capped event", store.dead)
	}
	if store.dead[0].lastError != "retry: notification backend busy" {
		t.Fatalf("last_error = %q, want the recorded retry failure text", store.dead[0].lastError)
	}
}

// TestRelayDrainDeadLettersPermanentHandlerFailure: any non-retry handler
// error is a permanent failure and dead-letters the row immediately, with
// the error text recorded as last_error.
func TestRelayDrainDeadLettersPermanentHandlerFailure(t *testing.T) {
	store := &fakeStore{events: []ClaimedEvent{
		{ID: "66666666-6666-6666-6666-666666666666", Type: "signal.created", Attempts: 1},
	}}
	relay := newRelay(t, store)
	if err := relay.Register("signal.created", func(ctx context.Context, event ClaimedEvent) error {
		return errors.New("recipient rejected the event")
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(store.acked) != 0 {
		t.Fatalf("acked = %v, want none", store.acked)
	}
	if len(store.dead) != 1 || store.dead[0].lastError != "recipient rejected the event" {
		t.Fatalf("dead-lettered = %+v, want the permanent failure recorded", store.dead)
	}
}

// TestRelayDrainAbortsOnStoreFailures: claim, ack and dead-letter store
// errors abort the drain with the cause reachable through errors.Is — the
// scheduler records the failed run, claimed rows keep their lease and are
// redelivered later (at-least-once, never lost).
func TestRelayDrainAbortsOnStoreFailures(t *testing.T) {
	event := ClaimedEvent{ID: "77777777-7777-7777-7777-777777777777", Type: "signal.created", Attempts: 1}

	t.Run("claim failure", func(t *testing.T) {
		cause := errors.New("connection refused")
		relay := newRelay(t, &fakeStore{claimErr: cause})
		err := relay.Drain(context.Background())
		if !errors.Is(err, cause) {
			t.Fatalf("Drain error = %v, want the claim cause reachable", err)
		}
	})

	t.Run("ack failure", func(t *testing.T) {
		cause := errors.New("connection lost")
		store := &fakeStore{events: []ClaimedEvent{event}, ackErr: cause}
		relay := newRelay(t, store)
		if err := relay.Register("signal.created", func(ctx context.Context, e ClaimedEvent) error { return nil }); err != nil {
			t.Fatalf("Register: %v", err)
		}
		err := relay.Drain(context.Background())
		if !errors.Is(err, cause) {
			t.Fatalf("Drain error = %v, want the ack cause reachable", err)
		}
		if len(store.dead) != 0 {
			t.Fatalf("dead-lettered = %+v, want none after a failed ack", store.dead)
		}
	})

	t.Run("dead-letter failure", func(t *testing.T) {
		cause := errors.New("connection lost")
		store := &fakeStore{events: []ClaimedEvent{event}, deadErr: cause}
		relay := newRelay(t, store)
		err := relay.Drain(context.Background()) // no handler registered → dead-letter path
		if !errors.Is(err, cause) {
			t.Fatalf("Drain error = %v, want the dead-letter cause reachable", err)
		}
		if len(store.acked) != 0 {
			t.Fatalf("acked = %v, want none after a failed dead-letter", store.acked)
		}
	})
}

// TestRelayDrainWithEmptyBatchDoesNothing: a drain that claims no rows
// succeeds without touching the store.
func TestRelayDrainWithEmptyBatchDoesNothing(t *testing.T) {
	store := &fakeStore{}
	relay := newRelay(t, store)
	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if store.limit != claimBatchSize {
		t.Fatalf("claim batch limit = %d, want the bounded batch %d", store.limit, claimBatchSize)
	}
	if len(store.acked) != 0 || len(store.dead) != 0 {
		t.Fatalf("acked = %v, dead-lettered = %+v; want no transitions on an empty batch", store.acked, store.dead)
	}
}

// TestRelayRegisterRejectsInvalidBindings: the dispatch registry is keyed
// by type and refuses wiring errors — an empty type, a nil handler and a
// duplicate type are all rejected.
func TestRelayRegisterRejectsInvalidBindings(t *testing.T) {
	relay := newRelay(t, &fakeStore{})
	handler := func(ctx context.Context, event ClaimedEvent) error { return nil }

	if err := relay.Register("", handler); err == nil {
		t.Fatal("Register with an empty type succeeded, want an error")
	}
	if err := relay.Register("signal.created", nil); err == nil {
		t.Fatal("Register with a nil handler succeeded, want an error")
	}
	if err := relay.Register("signal.created", handler); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := relay.Register("signal.created", handler); err == nil {
		t.Fatal("Registering the same type twice succeeded, want an error")
	}
}
