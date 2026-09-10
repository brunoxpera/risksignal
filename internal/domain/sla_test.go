package domain

import (
	"testing"
	"time"
)

// TestDefaultSLATimeProfile pins the ch. 9.4 / ARCH-004 §4.2 default
// durations and the presence/absence of each clock.
func TestDefaultSLATimeProfile(t *testing.T) {
	p := DefaultSLATimeProfile()
	cases := []struct {
		pri    Priority
		target SLATarget
		want   time.Duration
	}{
		{PriorityP1, SLATargetNotification, 5 * time.Minute},
		{PriorityP1, SLATargetAcknowledgement, 15 * time.Minute},
		{PriorityP1, SLATargetAssessment, 60 * time.Minute},
		{PriorityP1, SLATargetDecision, 4 * time.Hour},
		{PriorityP2, SLATargetNotification, 15 * time.Minute},
		{PriorityP2, SLATargetAcknowledgement, 1 * time.Hour},
		{PriorityP2, SLATargetAssessment, 4 * time.Hour},
		{PriorityP2, SLATargetDecision, 24 * time.Hour},
		{PriorityP3, SLATargetNotification, 0}, // no paging
		{PriorityP3, SLATargetAcknowledgement, 24 * time.Hour},
		{PriorityP3, SLATargetAssessment, 72 * time.Hour},
		{PriorityP3, SLATargetDecision, 0}, // after assessment
		{PriorityP4, SLATargetNotification, 0},
		{PriorityP4, SLATargetAcknowledgement, 0},
		{PriorityP4, SLATargetAssessment, 168 * time.Hour},
		{PriorityP4, SLATargetDecision, 0},
	}
	for _, tc := range cases {
		if got := p.Duration(tc.pri, tc.target); got != tc.want {
			t.Errorf("Duration(%s, %s) = %s, want %s", tc.pri, tc.target, got, tc.want)
		}
		if p.Defined(tc.pri, tc.target) != (tc.want > 0) {
			t.Errorf("Defined(%s, %s) = %v, want %v", tc.pri, tc.target, p.Defined(tc.pri, tc.target), tc.want > 0)
		}
	}
	if got := p.Targets(PriorityP1); len(got) != 4 {
		t.Errorf("Targets(P1) = %v, want all four", got)
	}
	if got := p.Targets(PriorityP3); len(got) != 2 || got[0] != SLATargetAcknowledgement || got[1] != SLATargetAssessment {
		t.Errorf("Targets(P3) = %v, want [acknowledgement assessment]", got)
	}
}

// TestNewSLATimeProfile validates the profile constructor.
func TestNewSLATimeProfile(t *testing.T) {
	scaled, err := NewSLATimeProfile(map[Priority]map[SLATarget]time.Duration{
		PriorityP1: {SLATargetNotification: 5 * time.Millisecond, SLATargetAcknowledgement: 15 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("NewSLATimeProfile: unexpected error: %v", err)
	}
	if got := scaled.Duration(PriorityP1, SLATargetNotification); got != 5*time.Millisecond {
		t.Errorf("scaled duration = %s, want 5ms", got)
	}
	// The accelerated profile must not leak into the defaults.
	if got := DefaultSLATimeProfile().Duration(PriorityP1, SLATargetNotification); got != 5*time.Minute {
		t.Errorf("default duration changed to %s", got)
	}

	if _, err := NewSLATimeProfile(map[Priority]map[SLATarget]time.Duration{Priority("P9"): {SLATargetAssessment: time.Hour}}); err == nil {
		t.Error("invalid priority: want error, got nil")
	}
	if _, err := NewSLATimeProfile(map[Priority]map[SLATarget]time.Duration{PriorityP1: {SLATarget("page"): time.Hour}}); err == nil {
		t.Error("invalid target: want error, got nil")
	}
	if _, err := NewSLATimeProfile(map[Priority]map[SLATarget]time.Duration{PriorityP1: {SLATargetAssessment: 0}}); err == nil {
		t.Error("non-positive duration: want error, got nil")
	}
}

// TestSlaClockLifecycle drives a clock through pause/resume/fulfil/tighten/
// reset and the effective-deadline computation with the accelerated profile.
func TestSlaClockLifecycle(t *testing.T) {
	profile := DefaultSLATimeProfile()
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	c, err := NewSlaClock("c1", "s1", SLATargetAcknowledgement, PriorityP2, profile, base)
	if err != nil {
		t.Fatalf("NewSlaClock: %v", err)
	}
	if !c.StartedAt.Equal(base) || !c.DeadlineAt.Equal(base.Add(time.Hour)) {
		t.Fatalf("clock = start %s deadline %s, want %s/%s", c.StartedAt, c.DeadlineAt, base, base.Add(time.Hour))
	}
	if c.Paused() || c.Fulfilled() {
		t.Fatal("a fresh clock must be open and running")
	}

	// A clock cannot be created where the profile defines none.
	if _, err := NewSlaClock("c2", "s1", SLATargetNotification, PriorityP3, profile, base); err == nil {
		t.Error("P3 notification clock: want error, got nil")
	}

	// Pause freezes the effective deadline; wall time passes.
	paused, err := c.Pause(base.Add(10 * time.Minute))
	if err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if !paused.Paused() {
		t.Fatal("clock must be paused")
	}
	if _, err := paused.Pause(base.Add(11 * time.Minute)); err == nil {
		t.Error("double pause: want error, got nil")
	}
	eff := paused.EffectiveDeadline(base.Add(25 * time.Minute))
	if want := base.Add(time.Hour + 15*time.Minute); !eff.Equal(want) {
		t.Errorf("paused effective deadline = %s, want %s", eff, want)
	}
	// While paused the remaining time is frozen: the clock can never become
	// overdue no matter how much wall time passes.
	if paused.Overdue(base.Add(70*time.Minute)) || paused.Overdue(base.Add(1000*time.Hour)) {
		t.Error("a paused clock must not be overdue while its remaining time is frozen")
	}

	// Resume accumulates the pause; the effective deadline stays shifted.
	resumed, err := paused.Resume(base.Add(25 * time.Minute))
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if resumed.Paused() {
		t.Fatal("clock must be running after resume")
	}
	if resumed.PausedSeconds != 15*60 {
		t.Errorf("paused_seconds = %d, want %d", resumed.PausedSeconds, 15*60)
	}
	if eff := resumed.EffectiveDeadline(base.Add(30 * time.Minute)); !eff.Equal(base.Add(time.Hour + 15*time.Minute)) {
		t.Errorf("resumed effective deadline = %s, want %s", eff, base.Add(time.Hour+15*time.Minute))
	}
	if _, err := resumed.Resume(base.Add(26 * time.Minute)); err == nil {
		t.Error("resume without pause: want error, got nil")
	}

	// Tighten: an earlier deadline shortens; a later one is a no-op.
	tight, err := resumed.Tighten(base.Add(30*time.Minute), 15*time.Minute)
	if err != nil {
		t.Fatalf("Tighten: %v", err)
	}
	if want := base.Add(45 * time.Minute); !tight.DeadlineAt.Equal(want) {
		t.Errorf("tightened deadline = %s, want %s", tight.DeadlineAt, want)
	}
	if kept, _ := tight.Tighten(base.Add(30*time.Minute), 2*time.Hour); !kept.DeadlineAt.Equal(base.Add(45 * time.Minute)) {
		t.Errorf("a longer duration must not move the deadline, got %s", kept.DeadlineAt)
	}

	// Fulfil is idempotent and closes the clock.
	ful, err := tight.Fulfil(base.Add(40 * time.Minute))
	if err != nil {
		t.Fatalf("Fulfil: %v", err)
	}
	if !ful.Fulfilled() {
		t.Fatal("clock must be fulfilled")
	}
	if ful.Overdue(base.Add(100 * time.Hour)) {
		t.Error("a fulfilled clock is never overdue")
	}
	again, err := ful.Fulfil(base.Add(50 * time.Minute))
	if err != nil || !again.FulfilledAt.Equal(base.Add(40*time.Minute)) {
		t.Errorf("Fulfil must be idempotent; got %v/%s", err, again.FulfilledAt)
	}
	if _, err := ful.Pause(base.Add(41 * time.Minute)); err == nil {
		t.Error("pausing a fulfilled clock: want error, got nil")
	}
	if _, err := ful.Tighten(base.Add(41*time.Minute), time.Minute); err == nil {
		t.Error("tightening a fulfilled clock: want error, got nil")
	}

	// Reset restarts the clock: cleared fulfilment and pause counters.
	reset, err := ful.Reset(base.Add(2*time.Hour), 30*time.Minute)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if reset.Fulfilled() || reset.Paused() || reset.PausedSeconds != 0 {
		t.Errorf("reset clock = fulfilled %v paused %v paused_seconds %d, want open/running/0", reset.Fulfilled(), reset.Paused(), reset.PausedSeconds)
	}
	if !reset.StartedAt.Equal(base.Add(2*time.Hour)) || !reset.DeadlineAt.Equal(base.Add(2*time.Hour+30*time.Minute)) {
		t.Errorf("reset clock = start %s deadline %s", reset.StartedAt, reset.DeadlineAt)
	}

	// Fulfilling a paused clock requires a resume first.
	p2, _ := c.Pause(base.Add(5 * time.Minute))
	if _, err := p2.Fulfil(base.Add(6 * time.Minute)); err == nil {
		t.Error("fulfilling a paused clock: want error, got nil")
	}
}
