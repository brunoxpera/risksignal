package main

// Composition-root test of the WP-1a.10 wiring as extended by WP-1b.06:
// runWithContext starts the scheduler loop wired to the outbox relay drain
// (one drain per scheduler cycle, ARCH-001 §2), the process logs a
// heartbeat and the outcome of each scheduler run, and cancelling the
// context shuts the loop down cleanly (Run returns nil). The signal path
// (run) is deliberately not driven with real signals inside tests — a
// signal sent to the test process could race the handler registration — so
// the SIGINT/SIGTERM behaviour is exercised by the manual verification of
// the work package instead.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// workerTestConfig returns a valid local configuration for the worker
// composition-root tests. The database URL points at a port that refuses
// connections: the pool is lazy (WP-1a.05) and the heartbeat needs no
// database, so no PostgreSQL is required — the relay drain fails per cycle
// and the test asserts the failure path of the wired loop.
func workerTestConfig(interval time.Duration) *config.Config {
	return &config.Config{
		SchemaVersion: config.SchemaVersion,
		Env:           "local",
		HTTP:          config.HTTP{Addr: "127.0.0.1:0"},
		Database:      config.Database{URL: "postgres://risksignal:risksignal@127.0.0.1:1/risksignal?sslmode=disable"},
		OIDC:          config.OIDC{Issuer: "http://127.0.0.1:9000/oidc"},
		Worker: config.Worker{
			Interval:            interval,
			SLAEvaluateInterval: time.Minute,
			SLAReminderCadence:  time.Hour,
			// The I6 export sweep cadence (WP-6.06): a required positive value;
			// the sweep scheduler never reaches the spool in this test (the
			// database URL is unreachable, so the cycle fails before it).
			ExportSweepInterval: 24 * time.Hour,
		},
		Export:    config.Export{Dir: "var/exports", TTL: 7 * 24 * time.Hour, MaxRows: 100000},
		Retention: config.Retention{ClosedSignalYears: 5, BatchSize: 500, Schedule: 30 * 24 * time.Hour},
	}
}

// lockedBuffer is a concurrency-safe log sink: the scheduler logs from its
// own goroutine while the test reads the transcript.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForLog polls the log transcript until it contains fragment or the
// timeout expires.
func waitForLog(t *testing.T, buf *lockedBuffer, fragment string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), fragment) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("log transcript does not contain %q within %s:\n%s", fragment, timeout, buf.String())
}

// TestRunWithContextHeartbeatsAndShutsDownCleanly drives the WP-1a.10 exit
// criterion through the composition root as wired by WP-1b.06: with the
// database unreachable the outbox relay drain fails every cycle — the loop
// logs the failed run (the last-successful-run timestamp stays zero), keeps
// beating its heartbeat and stays alive, and cancelling the context stops
// the loop cleanly, including the clean-shutdown record. The successful
// end-to-end drain against a real database is the relay integration test of
// this package (relay_integration_test.go).
func TestRunWithContextHeartbeatsAndShutsDownCleanly(t *testing.T) {
	buf := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runWithContext(ctx, workerTestConfig(10*time.Millisecond), logger) }()

	waitForLog(t, buf, "scheduler started", 5*time.Second)
	waitForLog(t, buf, "scheduler heartbeat", 5*time.Second)
	waitForLog(t, buf, "scheduler run failed", 5*time.Second)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runWithContext returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not shut down within 5s of cancellation")
	}
	transcript := buf.String()
	for _, want := range []string{"shutdown signal received", "scheduler stopped", "shutdown complete"} {
		if !strings.Contains(transcript, want) {
			t.Errorf("log transcript misses %q:\n%s", want, transcript)
		}
	}
}
