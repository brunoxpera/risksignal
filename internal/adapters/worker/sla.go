package worker

// The sla.evaluate scheduler (WP-4.05, ARCH-004 §4.4/§6): the periodic breach
// evaluation of the worker — a Tick invoked on a configured cadence through
// the injectable clock (ch. 7.2, TR-009; no real waiting in tests). Each due
// tick drives the application-side EvaluateSla use case (sla_evaluate.go): the
// open acknowledgement clocks past their effective deadline are scanned and,
// per unacknowledged P1, the first escalation is stamped once and later
// reminders are emitted per the configured cadence. The scheduler itself owns
// no SQL and no domain rule — it is the cadence and the wiring of the use case
// onto the worker loop; the escalation/reminder semantics and the transactional
// writes live in the application layer.
//
// The cadence is an injected configuration value (config worker.sla_evaluate_
// interval), never table state: the Tick runs when at least one interval has
// elapsed since the previous run on the injected clock, so a FakeClock in a
// test triggers a run without real waiting. The first Tick of a fresh process
// runs immediately (the scheduler has not run yet), matching the worker loop's
// "cycle at startup" convention.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// SlaEvaluatorRunner is the application surface the sla.evaluate scheduler
// drives (ARCH-004 §4.4): the breach-evaluation use case. The application-side
// *Service implements it; tests substitute a scripted fake.
type SlaEvaluatorRunner interface {
	EvaluateSla(ctx context.Context) (application.SlaEvaluateResult, error)
}

// SlaSchedule is the minute-cadence SLA evaluator of the worker loop. It is
// safe for use from one goroutine (the scheduler cycle); the cadence gate reads
// the injected clock.
type SlaSchedule struct {
	eval     SlaEvaluatorRunner
	clk      clock.Clock
	interval time.Duration
	logger   *slog.Logger

	// reg is the optional process metrics registry the scheduler records the
	// §16.2 SLA-escalation transitions on (ARCH-007 §5, WP-6.12 follow-up /
	// DEV-142, DEV-144). Wired through SetMetrics at the composition root; nil
	// disables the recording.
	reg *metrics.Registry

	// ran reports whether the scheduler has run at least once; lastRun is the
	// injected-clock instant of the last due tick. Together they gate the
	// cadence: the first tick runs immediately, every later tick waits out one
	// interval.
	ran     bool
	lastRun time.Time
}

// SetMetrics wires the optional process registry the scheduler records the
// §16.2 SLA-escalation transitions on (ARCH-007 §5, DEV-142). A nil registry
// disables the recording. It is called once at the composition root, before
// the worker loop starts.
func (s *SlaSchedule) SetMetrics(reg *metrics.Registry) { s.reg = reg }

// NewSlaSchedule assembles the sla.evaluate scheduler. eval must not be nil (a
// nil evaluator is a wiring error reported here); interval must be positive
// (the configured cadence, config worker.sla_evaluate_interval); a nil clock
// falls back to the real clock and a nil logger to a silent logger.
func NewSlaSchedule(eval SlaEvaluatorRunner, clk clock.Clock, interval time.Duration, logger *slog.Logger) (*SlaSchedule, error) {
	if eval == nil {
		return nil, fmt.Errorf("worker: sla scheduler: evaluator must not be nil")
	}
	if interval <= 0 {
		return nil, fmt.Errorf("worker: sla scheduler: interval must be positive (got %s)", interval)
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &SlaSchedule{eval: eval, clk: clk, interval: interval, logger: logger}, nil
}

// Tick runs one cadence-gated breach evaluation. The current instant is read
// through the injected clock; the tick is a no-op until one interval has
// elapsed since the previous due tick (the first tick runs immediately). A due
// tick drives EvaluateSla and logs its outcome; the returned error is the use
// case's, so the worker loop records a failed run but keeps beating.
func (s *SlaSchedule) Tick(ctx context.Context) error {
	now := s.clk.Now()
	if s.ran && now.Sub(s.lastRun) < s.interval {
		return nil // cadence gate: not due on the injected clock yet
	}
	s.ran = true
	s.lastRun = now

	res, err := s.eval.EvaluateSla(ctx)
	if err != nil {
		return err
	}
	// Record the escalation transitions of this pass (DEV-142/DEV-144): each
	// unacknowledged signal the evaluation escalated is one P1 SLA escalation.
	// Escalation is the exactly-once transition of a breach (the set-once
	// escalated_at guard), so a breached clock is counted once and never
	// re-counted on a later pass. "Breaches" remain a UI/FR-031 concern; the
	// recorded counter is the escalation transition.
	if s.reg != nil && res.Escalated > 0 {
		s.reg.Counter(metrics.NameSignalsSLAEscalationsTotal, metrics.HelpSignalsSLAEscalationsTotal).
			Add(float64(res.Escalated))
	}
	if res.Due > 0 || res.Escalated > 0 || res.Reminders > 0 {
		s.logger.Info("sla.evaluate run complete",
			slog.Int("due_ack_clocks", res.Due),
			slog.Int("escalated", res.Escalated),
			slog.Int("reminders", res.Reminders))
	} else {
		s.logger.Debug("sla.evaluate run complete (no due clock)")
	}
	return nil
}
