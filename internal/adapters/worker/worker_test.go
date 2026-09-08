package worker

// Tests of the WP-1a.10 scheduler loop: the worker starts, reports a
// heartbeat, records successful runs and shuts down cleanly when its
// context is cancelled; the clock port is injectable (FakeClock drives the
// worker's whole notion of time, TR-009); and failing runs keep the loop
// alive without advancing the last-successful-run timestamp (ch. 16.3).

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/platform/clock"
)

// discardLogger keeps the scheduler quiet in tests that assert on health
// state rather than on log output (the composition-root test in
// cmd/risksignal-worker asserts the heartbeat and shutdown records).
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitFor polls cond until it holds or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met within", timeout)
	}
}

// TestSchedulerHeartbeatsAndShutsDownCleanly drives the WP-1a.10 exit
// criterion with the production clock and a short interval: the scheduler
// records a heartbeat and a successful run without waiting for the first
// tick, keeps cycling on the ticker, and returns nil as soon as the context
// is cancelled.
func TestSchedulerHeartbeatsAndShutsDownCleanly(t *testing.T) {
	health := NewHealth()
	s, err := NewScheduler(10*time.Millisecond, clock.RealClock{}, discardLogger(), health)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// The very first cycle runs immediately: started, one heartbeat and one
	// successful run are recorded without waiting for the first interval.
	waitFor(t, 3*time.Second, func() bool {
		st := health.Snapshot()
		return !st.StartedAt.IsZero() && !st.LastBeat.IsZero() && !st.LastSuccess.IsZero()
	})
	firstSuccess := health.Snapshot().LastSuccess

	// The ticker keeps the loop alive: a second successful run proves the
	// periodic path works, not only the startup cycle.
	waitFor(t, 3*time.Second, func() bool {
		return health.Snapshot().LastSuccess.After(firstSuccess)
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancellation")
	}
}

// TestSchedulerUsesInjectedClock proves the clock port is injectable
// (TR-009): with a FakeClock the worker's notion of time is fully
// deterministic. The test jumps the clock forward by a day and the next
// tick records that time as the next successful run — a day passes in
// milliseconds of real time, the behaviour the later SLA and retention
// tests rely on.
func TestSchedulerUsesInjectedClock(t *testing.T) {
	t0 := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	fc := clock.NewFakeClock(t0)
	health := NewHealth()
	s, err := NewScheduler(5*time.Millisecond, fc, discardLogger(), health)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// The startup cycle records the fake start time and a successful run at
	// exactly that time.
	waitFor(t, 3*time.Second, func() bool {
		st := health.Snapshot()
		return st.StartedAt.Equal(t0) && !st.LastSuccess.IsZero()
	})
	if st := health.Snapshot(); !st.LastSuccess.Equal(t0) {
		t.Fatalf("LastSuccess = %v, want the fake time %v", st.LastSuccess, t0)
	}

	// Jump the clock forward: the next tick reads the advanced time and
	// records it as the next successful run.
	tomorrow := t0.Add(24 * time.Hour)
	fc.Set(tomorrow)
	waitFor(t, 3*time.Second, func() bool {
		return health.Snapshot().LastSuccess.Equal(tomorrow)
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancellation")
	}
}

// TestSchedulerSurvivesFailedRuns: a failing scheduler run must not stop
// the loop and must not advance the last-successful-run timestamp — the
// heartbeat keeps beating (ch. 16.3 distinguishes a live worker from work
// that completes). Once runs succeed again, the timestamp advances.
func TestSchedulerSurvivesFailedRuns(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)

	health := NewHealth()
	s, err := NewScheduler(5*time.Millisecond, clock.RealClock{}, discardLogger(), health)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	s.runOnce = func(context.Context) error {
		if fail.Load() {
			return errors.New("injected run failure")
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Failed runs: the loop beats more than once (startup cycle plus at
	// least one ticker cycle) but no successful run is recorded.
	waitFor(t, 3*time.Second, func() bool {
		st := health.Snapshot()
		return !st.LastBeat.IsZero() && st.LastBeat.After(st.StartedAt)
	})
	if st := health.Snapshot(); !st.LastSuccess.IsZero() {
		t.Fatalf("LastSuccess = %v, want zero after failed runs", st.LastSuccess)
	}

	// Runs recover: the next successful run advances the timestamp.
	fail.Store(false)
	waitFor(t, 3*time.Second, func() bool {
		return !health.Snapshot().LastSuccess.IsZero()
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancellation")
	}
}

// TestRunWithCancelledContext: a scheduler started with an already
// cancelled context stops immediately instead of running a cycle.
func TestRunWithCancelledContext(t *testing.T) {
	s, err := NewScheduler(10*time.Millisecond, clock.RealClock{}, discardLogger(), NewHealth())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v for a cancelled context, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s for a cancelled context")
	}
}
