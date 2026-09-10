package domain

import (
	"testing"
	"time"
)

// signalForOverride builds a P4 signal (candidate) to override.
func signalForOverride(t *testing.T) RiskSignal {
	t.Helper()
	s, err := NewRiskSignal("s1", "m1", PriorityFactors{
		Method:      MatchMethodCandidate,
		Confidence:  ConfidenceLow,
		Criticality: CriticalityNormal,
		Exposure:    ExposureInternal,
	})
	if err != nil {
		t.Fatalf("NewRiskSignal: %v", err)
	}
	return s
}

// TestRiskSignalOverrideRevert covers the ADR-015 auto_* mirror: an override
// moves the computed priority into AutoPriority and stamps reason/actor/time;
// a revert restores it and clears the four override fields.
func TestRiskSignalOverrideRevert(t *testing.T) {
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	s := signalForOverride(t)
	if s.Overridden() {
		t.Fatal("a fresh signal must not be overridden")
	}
	if s.Priority != PriorityP4 {
		t.Fatalf("base priority = %s, want P4", s.Priority)
	}

	over, err := s.Override(PriorityP1, "boss says urgent", "actor-1", at)
	if err != nil {
		t.Fatalf("Override: %v", err)
	}
	if !over.Overridden() {
		t.Fatal("override must set the override marker")
	}
	if over.Priority != PriorityP1 {
		t.Errorf("effective priority = %s, want P1", over.Priority)
	}
	if over.AutoPriority == nil || *over.AutoPriority != PriorityP4 {
		t.Errorf("auto_priority = %v, want the computed P4", over.AutoPriority)
	}
	if over.OverrideReason != "boss says urgent" || over.OverrideActorID != "actor-1" || !over.OverrideAt.Equal(at) {
		t.Errorf("override stamps = %q/%q/%s, want reason/actor/time", over.OverrideReason, over.OverrideActorID, over.OverrideAt)
	}
	// The original value is untouched (value semantics).
	if s.Overridden() || s.Priority != PriorityP4 {
		t.Error("Override must not mutate the receiver")
	}

	// A second override on an already-overridden signal is an error.
	if _, err := over.Override(PriorityP2, "again", "actor-2", at); err == nil {
		t.Error("double override: want error, got nil")
	}

	rev, err := over.Revert()
	if err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if rev.Overridden() {
		t.Error("revert must clear the override marker")
	}
	if rev.Priority != PriorityP4 {
		t.Errorf("reverted priority = %s, want the computed P4", rev.Priority)
	}
	if rev.OverrideReason != "" || rev.OverrideActorID != "" || !rev.OverrideAt.IsZero() {
		t.Errorf("revert must clear the override stamps, got %q/%q/%s", rev.OverrideReason, rev.OverrideActorID, rev.OverrideAt)
	}
	if _, err := rev.Revert(); err == nil {
		t.Error("revert without an override: want error, got nil")
	}
}

// TestRiskSignalOverrideValidation pins the mandatory override arguments.
func TestRiskSignalOverrideValidation(t *testing.T) {
	at := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	s := signalForOverride(t)
	cases := []struct {
		name     string
		priority Priority
		reason   string
		actor    string
		at       time.Time
	}{
		{"invalid priority", Priority("P9"), "why", "a", at},
		{"empty reason", PriorityP1, "", "a", at},
		{"empty actor", PriorityP1, "why", "", at},
		{"zero instant", PriorityP1, "why", "a", time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Override(tc.priority, tc.reason, tc.actor, tc.at); err == nil {
				t.Errorf("Override(%s): want error, got nil", tc.name)
			}
		})
	}
}
