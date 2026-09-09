package application

// Internal unit tests of the source scheduling machinery (WP-2.08,
// DEV-042, ARCH-002 §5): the due-slot derivation of the schedule strings
// and the dedupe key shapes of the source.fetch/source.normalize jobs
// (ch. 14.1). These are unexported helpers of the application package, so
// the tests live inside it (same convention as
// run_synthetic_source_internal_test.go).

import (
	"testing"
	"time"
)

// TestDueScheduleSlotPinsSlotBoundaries pins the schedule grammar of the
// sources.schedule column (ARCH-002 §1: "@hourly", "@daily") and the slot
// derivation: a slot is the period's UTC boundary at or before now, so an
// hourly source is due once per hour and a daily source once per UTC day,
// whatever the worker's cycle time. Unsupported strings are not due.
func TestDueScheduleSlotPinsSlotBoundaries(t *testing.T) {
	day := time.Date(2026, 9, 9, 9, 30, 45, 0, time.UTC) // 09:30:45Z on 2026-09-09

	cases := []struct {
		schedule string
		now      time.Time
		want     time.Time
	}{
		{"@hourly", day, time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC)},
		{"@hourly", time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC), time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC)}, // on the boundary: due now
		{"@daily", day, time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)},
		{"@daily", time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)},
		{"@daily", time.Date(2026, 9, 9, 23, 59, 59, 0, time.UTC), time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)},
		// A non-UTC clock instant still lands on the UTC boundary (the
		// slots are UTC by construction).
		{"@daily", time.Date(2026, 9, 9, 23, 30, 0, 0, time.FixedZone("off", 7200)), time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		got, ok := dueScheduleSlot(tc.schedule, tc.now)
		if !ok {
			t.Errorf("dueScheduleSlot(%q, %v): ok = false, want the slot %v", tc.schedule, tc.now, tc.want)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("dueScheduleSlot(%q, %v) = %v, want %v", tc.schedule, tc.now, got, tc.want)
		}
	}
}

// TestDueScheduleSlotRejectsUnsupportedSchedules: a schedule string outside
// the supported grammar is not due — the scheduler skips the source and
// reports it instead of failing the cycle.
func TestDueScheduleSlotRejectsUnsupportedSchedules(t *testing.T) {
	now := time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)
	for _, schedule := range []string{"", "   ", "@weekly", "0 * * * *", "24h", "@midnight"} {
		if slot, ok := dueScheduleSlot(schedule, now); ok {
			t.Errorf("dueScheduleSlot(%q) = %v, ok = true; want not due", schedule, slot)
		}
	}
}

// TestSourceJobDedupeKeys pins the ch. 14.1 dedupe key shapes of the two
// source job types: source.fetch keys carry the source id plus the plan
// time (RFC 3339 UTC — one key per schedule slot) or the manual request id,
// namespaced so the two enqueue paths can never collide; the
// source.normalize key carries the raw record id plus the adapter's
// normalizer_version.
func TestSourceJobDedupeKeys(t *testing.T) {
	slot := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)

	if got := sourceFetchPlanDedupeKey("src-1", slot); got != "source.fetch:plan:src-1:2026-09-09T00:00:00Z" {
		t.Errorf("sourceFetchPlanDedupeKey = %q, want source.fetch:plan:src-1:2026-09-09T00:00:00Z", got)
	}
	// The same instant in another zone or with sub-second precision maps to
	// the same canonical key (slots are exact second boundaries).
	if got := sourceFetchPlanDedupeKey("src-1", slot.Add(0).In(time.FixedZone("off", 7200))); got != "source.fetch:plan:src-1:2026-09-09T00:00:00Z" {
		t.Errorf("sourceFetchPlanDedupeKey (non-UTC instant) = %q, want the canonical UTC key", got)
	}
	if got := sourceFetchManualDedupeKey("src-1", "req-42"); got != "source.fetch:manual:src-1:req-42" {
		t.Errorf("sourceFetchManualDedupeKey = %q, want source.fetch:manual:src-1:req-42", got)
	}
	// Plan and manual keys are namespaced apart: a request id that happens
	// to equal a plan-time string cannot collide with the scheduled key.
	if got := sourceFetchManualDedupeKey("src-1", "plan:src-1:2026-09-09T00:00:00Z"); got == sourceFetchPlanDedupeKey("src-1", slot) {
		t.Errorf("manual key must not collide with the plan key of the same source")
	}
	if got := sourceNormalizeDedupeKey("raw-1", "kev-normalizer-v1"); got != "source.normalize:raw-1:kev-normalizer-v1" {
		t.Errorf("sourceNormalizeDedupeKey = %q, want source.normalize:raw-1:kev-normalizer-v1", got)
	}
}
