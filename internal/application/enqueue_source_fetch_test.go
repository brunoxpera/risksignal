package application_test

// Unit tests of the source run enqueue use cases (WP-2.08, DEV-042,
// ARCH-002 §5) with the in-memory harness: EnqueueDueSourceFetches — the
// scheduler scan that enqueues one source.fetch job per due schedule slot
// (dedupe source_id + plan_time; repeated cycles no-op on the outbox UQ)
// and skips unparsable schedules without failing — and
// EnqueueManualSourceFetch — the manual trigger that bypasses the schedule
// (dedupe source_id + request_id; idempotent per request id).

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
)

// fetchJobOf decodes the outbox payload of one source.fetch event.
func fetchJobOf(t *testing.T, ev application.OutboxEvent) application.SourceFetchJobPayload {
	t.Helper()
	if ev.Type != application.EventTypeSourceFetch {
		t.Fatalf("event type = %q, want %q", ev.Type, application.EventTypeSourceFetch)
	}
	var payload application.SourceFetchJobPayload
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("decode fetch payload %s: %v", ev.Payload, err)
	}
	return payload
}

// TestEnqueueDueSourceFetchesEnqueuesOneJobPerDueSlot drives the scheduler
// scan: enabled scheduled sources get one source.fetch job for their due
// slot — the daily source for today's UTC midnight, the hourly source for
// the current hour — with available_at = the scheduled time and the
// ch. 14.1 plan dedupe key; an unparsable schedule is skipped and reported,
// never fatal.
func TestEnqueueDueSourceFetchesEnqueuesOneJobPerDueSlot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.scheduled = []application.ScheduledSource{
		{ID: "src-daily", Type: application.SourceTypeKEV, Schedule: "@daily"},
		{ID: "src-hourly", Type: application.SourceTypeNVD, Schedule: "@hourly"},
		{ID: "src-bad", Type: application.SourceTypeKEV, Schedule: "0 * * * *"},
	}

	res, err := h.svc.EnqueueDueSourceFetches(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueSourceFetches: %v", err)
	}
	if res.Enqueued != 2 || res.AlreadyQueued != 0 {
		t.Fatalf("result = %+v, want 2 enqueued jobs", res)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "src-bad" {
		t.Fatalf("skipped = %v, want the source with the unparsable schedule", res.Skipped)
	}

	if len(h.db.outboxEvents) != 2 {
		t.Fatalf("outbox events = %d, want the 2 fetch jobs", len(h.db.outboxEvents))
	}
	wantKeys := map[string]time.Time{
		"source.fetch:plan:src-daily:2026-09-09T00:00:00Z":  time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
		"source.fetch:plan:src-hourly:2026-09-09T09:00:00Z": time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC),
	}
	for _, ev := range h.db.outboxEvents {
		slot, wantKey := wantKeys[ev.DedupeKey]
		if !wantKey {
			t.Fatalf("unexpected outbox event with dedupe key %q", ev.DedupeKey)
		}
		delete(wantKeys, ev.DedupeKey)
		if !ev.AvailableAt.Equal(slot) {
			t.Errorf("job %s: available_at = %v, want the scheduled time %v", ev.DedupeKey, ev.AvailableAt, slot)
		}
		payload := fetchJobOf(t, ev)
		if payload.SourceID == "" || !payload.PlanTime.Equal(slot) || payload.RequestID != "" {
			t.Errorf("job %s: payload = %+v, want the source id and the plan time", ev.DedupeKey, payload)
		}
	}
	if len(wantKeys) != 0 {
		t.Fatalf("missing jobs for slots %v", wantKeys)
	}

	// A second scan on the same clock: every slot is already covered — the
	// outbox UQ (dedupe_key) turns the re-enqueue into a no-op and no new
	// row lands (ADR-012).
	res, err = h.svc.EnqueueDueSourceFetches(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueSourceFetches (repeat): %v", err)
	}
	if res.Enqueued != 0 || res.AlreadyQueued != 2 {
		t.Fatalf("repeat result = %+v, want 2 already-queued no-ops", res)
	}
	if len(h.db.outboxEvents) != 2 {
		t.Fatalf("outbox events after repeat = %d, want 2 — the dedupe held", len(h.db.outboxEvents))
	}

	// One hour later the hourly slot advances: a fresh job for 10:00Z is
	// enqueued; the daily slot is still the same day's.
	h.clock.Advance(time.Hour)
	res, err = h.svc.EnqueueDueSourceFetches(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueSourceFetches (next hour): %v", err)
	}
	if res.Enqueued != 1 || res.AlreadyQueued != 1 {
		t.Fatalf("next-hour result = %+v, want the new hourly slot enqueued", res)
	}
	found := false
	for _, ev := range h.db.outboxEvents {
		if ev.DedupeKey == "source.fetch:plan:src-hourly:2026-09-09T10:00:00Z" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no outbox row for the advanced hourly slot 10:00Z")
	}
}

// TestEnqueueManualSourceFetchTriggersIdempotentByRequestID drives the
// manual trigger: the source.fetch job is enqueued due immediately with the
// manual dedupe key (source_id + request_id), a repeated trigger with the
// same request id is a no-op reported as AlreadyQueued, and a fresh request
// id always enqueues a fresh job — the schedule is bypassed entirely.
func TestEnqueueManualSourceFetchTriggersIdempotentByRequestID(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.db.sources = append(h.db.sources, application.SourceDescriptor{
		ID:   "src-kev",
		Type: application.SourceTypeKEV,
	})
	// The source has no schedule at all: a manual trigger must still work.
	h.db.scheduled = nil

	res, err := h.svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID:  "src-kev",
		RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("EnqueueManualSourceFetch: %v", err)
	}
	if res.AlreadyQueued || res.SourceType != application.SourceTypeKEV || res.RequestID != "req-1" {
		t.Fatalf("result = %+v, want a fresh job for the kev source", res)
	}
	if res.DedupeKey != "source.fetch:manual:src-kev:req-1" {
		t.Fatalf("dedupe key = %q, want source.fetch:manual:src-kev:req-1", res.DedupeKey)
	}
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox events = %d, want 1", len(h.db.outboxEvents))
	}
	ev := h.db.outboxEvents[0]
	payload := fetchJobOf(t, ev)
	if payload.SourceID != "src-kev" || payload.RequestID != "req-1" || !payload.PlanTime.IsZero() {
		t.Fatalf("payload = %+v, want the source id and the manual request id", payload)
	}
	if !ev.AvailableAt.Equal(fixedNow) {
		t.Fatalf("available_at = %v, want now %v — a manual run bypasses the schedule", ev.AvailableAt, fixedNow)
	}

	// The same request id again: no new job.
	res, err = h.svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID:  "src-kev",
		RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("EnqueueManualSourceFetch (repeat): %v", err)
	}
	if !res.AlreadyQueued {
		t.Fatalf("repeat result = %+v, want AlreadyQueued", res)
	}
	if len(h.db.outboxEvents) != 1 {
		t.Fatalf("outbox events after repeat = %d, want 1 — the dedupe held", len(h.db.outboxEvents))
	}

	// A fresh request id: a new job, whatever the schedule says.
	res, err = h.svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID:  "src-kev",
		RequestID: "req-2",
	})
	if err != nil {
		t.Fatalf("EnqueueManualSourceFetch (fresh request): %v", err)
	}
	if res.AlreadyQueued || res.DedupeKey != "source.fetch:manual:src-kev:req-2" {
		t.Fatalf("fresh-request result = %+v, want a new job", res)
	}
	if len(h.db.outboxEvents) != 2 {
		t.Fatalf("outbox events = %d, want 2", len(h.db.outboxEvents))
	}
}

// TestEnqueueManualSourceFetchValidation covers the ch. 5.2 error classes
// of the manual trigger: an unknown source is not-found, an empty request
// id is a validation error, and no job is ever appended on a failure.
func TestEnqueueManualSourceFetchValidation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	_, err := h.svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID:  "no-such-source",
		RequestID: "req-1",
	})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("unknown source error = %v, want not-found", err)
	}

	_, err = h.svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID:  "src-x",
		RequestID: "",
	})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("empty request id error = %v, want validation", err)
	}

	if len(h.db.outboxEvents) != 0 {
		t.Fatalf("outbox events = %d, want 0 after the validation failures", len(h.db.outboxEvents))
	}
}
