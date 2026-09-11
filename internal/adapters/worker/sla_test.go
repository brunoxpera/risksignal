package worker

// Tests of the WP-4.05 sla.evaluate scheduler (sla.go, ARCH-004 §4.4): the
// cadence gate reads the injected FakeClock — the first tick runs immediately,
// a tick inside the interval is a no-op, and a tick once the interval has
// elapsed drives the wired evaluation. No real waiting.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// scriptedSlaEvaluator is a SlaEvaluatorRunner whose outcome the test fixes;
// it records the call count.
type scriptedSlaEvaluator struct {
	res   application.SlaEvaluateResult
	err   error
	calls int
}

func (e *scriptedSlaEvaluator) EvaluateSla(_ context.Context) (application.SlaEvaluateResult, error) {
	e.calls++
	return e.res, e.err
}

var _ SlaEvaluatorRunner = (*scriptedSlaEvaluator)(nil)

// TestSlaScheduleTickHonoursTheCadence proves the minute cadence is gated on
// the injected clock: the first tick evaluates immediately, a tick inside the
// interval is a no-op, and a tick after the interval elapsed evaluates again.
func TestSlaScheduleTickHonoursTheCadence(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	clk := clock.NewFakeClock(start)
	eval := &scriptedSlaEvaluator{res: application.SlaEvaluateResult{Due: 1}}

	sched, err := NewSlaSchedule(eval, clk, time.Minute, discardLogger())
	if err != nil {
		t.Fatalf("NewSlaSchedule: %v", err)
	}

	// First tick: runs immediately.
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("Tick (first): %v", err)
	}
	if eval.calls != 1 {
		t.Fatalf("evaluations after the first tick = %d, want 1", eval.calls)
	}

	// A tick inside the interval is a no-op.
	clk.Advance(30 * time.Second)
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("Tick (within interval): %v", err)
	}
	if eval.calls != 1 {
		t.Fatalf("evaluations after a tick inside the interval = %d, want 1", eval.calls)
	}

	// Once the interval elapsed the next tick evaluates again.
	clk.Advance(31 * time.Second)
	if err := sched.Tick(ctx); err != nil {
		t.Fatalf("Tick (interval elapsed): %v", err)
	}
	if eval.calls != 2 {
		t.Fatalf("evaluations after the interval elapsed = %d, want 2", eval.calls)
	}
}

// TestSlaScheduleTickPropagatesEvaluatorError: a failing evaluation is
// surfaced so the worker loop records a failed run (and keeps beating).
func TestSlaScheduleTickPropagatesEvaluatorError(t *testing.T) {
	sched, err := NewSlaSchedule(
		&scriptedSlaEvaluator{err: errors.New("db down")},
		clock.NewFakeClock(time.Now()),
		time.Minute,
		discardLogger(),
	)
	if err != nil {
		t.Fatalf("NewSlaSchedule: %v", err)
	}
	if err := sched.Tick(context.Background()); err == nil {
		t.Fatal("Tick returned nil, want the evaluator's error")
	}
}

// TestNewSlaScheduleRejectsWiringErrors: a nil evaluator or a non-positive
// interval is a wiring error.
func TestNewSlaScheduleRejectsWiringErrors(t *testing.T) {
	if s, err := NewSlaSchedule(nil, clock.NewFakeClock(time.Now()), time.Minute, discardLogger()); err == nil || s != nil {
		t.Fatalf("NewSlaSchedule(nil) = %v/%v, want a wiring error", s, err)
	}
	if s, err := NewSlaSchedule(&scriptedSlaEvaluator{}, clock.NewFakeClock(time.Now()), 0, discardLogger()); err == nil || s != nil {
		t.Fatalf("NewSlaSchedule(zero interval) = %v/%v, want a wiring error", s, err)
	}
}

// TestSlaScheduleRecordsBreachTransitions proves the DEV-142 SLA-breach
// recording: each escalation transition of an evaluation pass is counted in
// signals_sla_breaches_total (the exactly-once breach transition).
func TestSlaScheduleRecordsBreachTransitions(t *testing.T) {
	clk := clock.NewFakeClock(time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC))
	eval := &scriptedSlaEvaluator{res: application.SlaEvaluateResult{Due: 3, Escalated: 2, Reminders: 1}}

	reg := metrics.New()
	metrics.RegisterStandard(reg)

	sched, err := NewSlaSchedule(eval, clk, time.Minute, discardLogger())
	if err != nil {
		t.Fatalf("NewSlaSchedule: %v", err)
	}
	sched.SetMetrics(reg)

	if err := sched.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	var got float64
	for _, s := range reg.Snapshot() {
		if s.Name == metrics.NameSignalsSLABreachesTotal {
			got = s.Value
		}
	}
	if got != 2 {
		t.Fatalf("signals_sla_breaches_total = %v, want 2 (the escalation transitions)", got)
	}
}
