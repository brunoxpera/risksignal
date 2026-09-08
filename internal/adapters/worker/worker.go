// Package worker implements the background worker process role of the
// implementation concept (ch. 4.1 "Prozessrollen"): source fetching,
// normalisation, matching, prioritisation, SLA escalation, retention,
// outbox and notifications are driven from here, one process role away from
// the HTTP server. The worker appears as an adapter in the concept's layer
// diagram (ch. 2.2: Worker/Scheduler under "Adapter"), so this package lives
// under internal/adapters and is allowed to depend on the application and
// domain layers once job dispatch lands.
//
// WP-1a.10 scaffolds the loop without job types: the scheduler ticks on the
// configured interval (config worker.interval), emits a heartbeat, records
// worker health (heartbeat and last successful run, concept ch. 16.3) and
// stops cleanly when its context is cancelled. Time is read through the
// injectable clock port of internal/platform/clock (ch. 7.2, TR-009), so
// tests drive the worker's notion of time with a FakeClock instead of
// waiting. Job polling and dispatch land in later work packages (ch. 14);
// heartbeat and health state are the observable contract the
// operator-facing reporting will read.
package worker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/xpera/risksignal/internal/platform/clock"
)

// Health is the observable health state of the worker (concept ch. 16.3:
// worker health shows heartbeat, job backlog and last successful scheduler
// run). The WP-1a.10 scaffold records heartbeat and last successful run;
// the job backlog arrives with the job types of a later work package.
//
// The scheduler loop records into Health on its own goroutine while future
// health reporters (logs, metrics, the operator-facing worker-health view)
// read snapshots, so every method is safe for concurrent use.
type Health struct {
	mu          sync.Mutex
	startedAt   time.Time // the scheduler loop started
	lastBeat    time.Time // last heartbeat: the loop proved itself alive
	lastRunAt   time.Time // the last scheduler run ended, successful or not
	lastSuccess time.Time // the last successful scheduler run ended
}

// NewHealth returns an empty worker health state.
func NewHealth() *Health {
	return &Health{}
}

// Start marks the scheduler loop as started at at.
func (h *Health) Start(at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.startedAt = at
}

// Beat records a heartbeat at at: the scheduler loop is alive. A heartbeat
// is independent of run outcomes — the loop keeps beating while runs fail.
func (h *Health) Beat(at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastBeat = at
}

// RunFinished records that a scheduler run ended at at. A non-nil err means
// the run failed: the last successful run timestamp stays at its previous
// value, so operators can tell a loop that is alive from work that actually
// completes (ch. 16.3).
func (h *Health) RunFinished(at time.Time, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastRunAt = at
	if err == nil {
		h.lastSuccess = at
	}
}

// State is a point-in-time snapshot of the worker health. Zero times mean
// "not yet": a worker that has never completed a run reports a zero
// LastSuccess until the first one finishes.
type State struct {
	StartedAt   time.Time
	LastBeat    time.Time
	LastRunAt   time.Time
	LastSuccess time.Time
}

// Snapshot returns a consistent view of the health state.
func (h *Health) Snapshot() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	return State{
		StartedAt:   h.startedAt,
		LastBeat:    h.lastBeat,
		LastRunAt:   h.lastRunAt,
		LastSuccess: h.lastSuccess,
	}
}

// Scheduler drives the periodic worker loop (WP-1a.10): every interval it
// beats a heartbeat and executes one scheduler run. The run currently does
// nothing — job types do not exist yet — and the loop is the skeleton the
// job-polling work packages fill in (ch. 14).
type Scheduler struct {
	interval time.Duration
	clk      clock.Clock
	logger   *slog.Logger
	health   *Health

	// runOnce executes one scheduler run. The scaffold ships a no-op that
	// succeeds immediately; later work packages replace it with job polling
	// and dispatch. A run returning an error keeps the loop alive (the next
	// cycle still beats) but does not advance the last successful run.
	runOnce func(ctx context.Context) error
}

// NewScheduler builds a scheduler that runs one cycle every interval,
// reading time through clk and recording health into health. A nil clk,
// logger or health falls back to the production clock, a silent logger or a
// fresh health state respectively. interval must be positive — config
// validation (WP-1a.02) enforces it for configured values; anything else is
// a programming error reported here.
func NewScheduler(interval time.Duration, clk clock.Clock, logger *slog.Logger, health *Health) (*Scheduler, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("worker: scheduler interval must be positive (got %s)", interval)
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if health == nil {
		health = NewHealth()
	}
	return &Scheduler{
		interval: interval,
		clk:      clk,
		logger:   logger,
		health:   health,
		runOnce:  func(context.Context) error { return nil }, // no job types yet (WP-1a.10)
	}, nil
}

// Run runs the scheduler loop until ctx is cancelled, then stops cleanly
// and returns nil. The first cycle runs immediately at startup so a fresh
// worker reports a heartbeat and a completed run without waiting for the
// first interval; every later cycle runs on one tick of a time.Ticker with
// the configured interval. Cancellation is observed between cycles: a run
// that ignores ctx keeps running until it returns, and the caller's
// shutdown grace period (cmd/risksignal-worker) bounds that wait. Run
// returns nil for a cancelled context; a future fatal loop error would be
// returned here.
func (s *Scheduler) Run(ctx context.Context) error {
	s.health.Start(s.clk.Now())
	s.logger.Info("scheduler started", slog.String("interval", s.interval.String()))
	if err := ctx.Err(); err != nil {
		s.logger.Info("scheduler stopped before first cycle")
		return nil
	}

	s.runCycle(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scheduler stopped")
			return nil
		case <-ticker.C:
			s.runCycle(ctx)
		}
	}
}

// runCycle executes one scheduler cycle: heartbeat first, then the
// scheduler run, then the outcome record. The heartbeat precedes the run so
// the worker proves it is alive even while a run is still executing.
func (s *Scheduler) runCycle(ctx context.Context) {
	if err := ctx.Err(); err != nil {
		return // context cancelled between cycles; Run handles the exit
	}
	beat := s.clk.Now()
	s.health.Beat(beat)
	s.logger.Info("scheduler heartbeat",
		timeAttr("heartbeat_at", beat),
		timeAttr("last_success_at", s.health.Snapshot().LastSuccess))

	err := s.runOnce(ctx)
	finishedAt := s.clk.Now()
	s.health.RunFinished(finishedAt, err)
	if err != nil {
		s.logger.Warn("scheduler run failed",
			slog.Any("error", err),
			timeAttr("run_finished_at", finishedAt),
			timeAttr("last_success_at", s.health.Snapshot().LastSuccess))
		return
	}
	s.logger.Info("scheduler run complete", timeAttr("run_finished_at", finishedAt))
}

// timeAttr renders a timestamp attribute, mapping the zero time to the
// string "never" so a "last successful run" that has not happened yet stays
// readable in the log instead of rendering as the year 1.
func timeAttr(name string, t time.Time) slog.Attr {
	if t.IsZero() {
		return slog.String(name, "never")
	}
	return slog.Time(name, t)
}
