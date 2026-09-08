package main

// Composition-root test of the WP-1a.10 wiring: runWithContext starts the
// scheduler loop, the process logs a heartbeat and completed scheduler
// runs, and cancelling the context shuts the loop down cleanly (Run returns
// nil). The signal path (run) is deliberately not driven with real signals
// inside tests — a signal sent to the test process could race the handler
// registration — so the SIGINT/SIGTERM behaviour is exercised by the manual
// verification of the work package instead.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/platform/config"
)

// workerTestConfig returns a valid local configuration for the worker
// composition-root tests. The database URL points at a port that refuses
// connections: the pool is lazy (WP-1a.05) and the heartbeat needs no
// database, so no PostgreSQL is required.
func workerTestConfig(interval time.Duration) *config.Config {
	return &config.Config{
		SchemaVersion: config.SchemaVersion,
		Env:           "local",
		HTTP:          config.HTTP{Addr: "127.0.0.1:0"},
		Database:      config.Database{URL: "postgres://risksignal:risksignal@127.0.0.1:1/risksignal?sslmode=disable"},
		OIDC:          config.OIDC{Issuer: "http://127.0.0.1:9000/oidc"},
		Worker:        config.Worker{Interval: interval},
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
// criterion through the composition root: the worker starts, emits a
// heartbeat and completed-run records, and cancelling the context stops the
// loop cleanly — including the clean-shutdown record.
func TestRunWithContextHeartbeatsAndShutsDownCleanly(t *testing.T) {
	buf := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runWithContext(ctx, workerTestConfig(10*time.Millisecond), logger) }()

	waitForLog(t, buf, "scheduler started", 5*time.Second)
	waitForLog(t, buf, "scheduler heartbeat", 5*time.Second)
	waitForLog(t, buf, "scheduler run complete", 5*time.Second)

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
