package clock

import (
	"testing"
	"time"
)

// TestRealClockTracksWallTime bounds RealClock.Now between two wall-clock
// reads around the call.
func TestRealClockTracksWallTime(t *testing.T) {
	before := time.Now().Add(-time.Second)
	got := RealClock{}.Now()
	after := time.Now().Add(time.Second)
	if got.Before(before) || got.After(after) {
		t.Errorf("RealClock.Now() = %v, want a time between %v and %v", got, before, after)
	}
}

// TestFakeClockSetAndAdvance drives the fake clock deterministically: the
// test fixes and moves the time and reads it back — the behaviour every
// SLA- and retention test of TR-009 will rely on.
func TestFakeClockSetAndAdvance(t *testing.T) {
	t0 := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	fc := NewFakeClock(t0)
	if got := fc.Now(); !got.Equal(t0) {
		t.Fatalf("Now() = %v, want the initial time %v", got, t0)
	}

	t1 := t0.Add(24 * time.Hour)
	fc.Set(t1)
	if got := fc.Now(); !got.Equal(t1) {
		t.Errorf("Now() after Set = %v, want %v", got, t1)
	}

	fc.Advance(90 * time.Minute)
	want := t1.Add(90 * time.Minute)
	if got := fc.Now(); !got.Equal(want) {
		t.Errorf("Now() after Advance = %v, want %v", got, want)
	}
}
