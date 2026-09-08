// Package clock provides the injectable clock port of the platform
// (implementation concept ch. 7.2 "Identitäten und Zeit": the system clock
// is used through an injectable port so that SLA and retention logic can be
// tested without real waiting — TR-009, TAT-08, TAT-09).
//
// Production code depends on the Clock interface and receives RealClock;
// tests inject FakeClock and drive time deterministically. FakeClock lives
// in this package on purpose: every later SLA and retention test shares the
// same deterministic clock instead of re-implementing one.
package clock

import (
	"sync"
	"time"
)

// Clock is the injectable time source of the platform. Code that makes
// time-based decisions (worker heartbeats, SLA deadlines, retention
// cutoffs) depends on this interface and never reads the wall clock
// directly, so tests can simulate arbitrary points in time.
type Clock interface {
	// Now returns the current time as seen by this clock.
	Now() time.Time
}

// RealClock is the production clock: Now returns the wall-clock time.
type RealClock struct{}

// Now implements Clock with the wall-clock time.
func (RealClock) Now() time.Time { return time.Now() }

// FakeClock is a manually driven clock for tests: Now returns the time a
// test last set with Set or moved with Advance, starting at the time passed
// to NewFakeClock. It is safe for concurrent use, so a worker or domain
// goroutine can read Now while the test advances time.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a fake clock reading at.
func NewFakeClock(at time.Time) *FakeClock {
	return &FakeClock{now: at}
}

// Now implements Clock.
func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Set fixes the clock to at.
func (f *FakeClock) Set(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = at
}

// Advance moves the clock forward by d; a negative d moves it back.
func (f *FakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Compile-time assertions: both clocks satisfy the port.
var (
	_ Clock = RealClock{}
	_ Clock = (*FakeClock)(nil)
)
