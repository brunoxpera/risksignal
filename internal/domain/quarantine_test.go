package domain

import (
	"strings"
	"testing"
)

// TestParseQuarantineStatus covers every allowed status value (ARCH-002
// §3 CHECK, §4) plus invalid input handling.
func TestParseQuarantineStatus(t *testing.T) {
	all := []QuarantineStatus{
		QuarantineStatusNew,
		QuarantineStatusAcknowledged,
		QuarantineStatusReadyForRetry,
		QuarantineStatusResolved,
	}
	for _, want := range all {
		got, err := ParseQuarantineStatus(string(want))
		if err != nil {
			t.Errorf("ParseQuarantineStatus(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseQuarantineStatus(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("QuarantineStatus %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "New", "OPEN", "ready", "resolved ", "ack", "pending"} {
		if _, err := ParseQuarantineStatus(s); err == nil {
			t.Errorf("ParseQuarantineStatus(%q): want error, got nil", s)
		}
	}
	if QuarantineStatus("").Valid() {
		t.Error("zero-value QuarantineStatus must not be Valid")
	}
}

// TestNewQuarantine covers the isolation path (ARCH-002 §4 "(create) →
// new"): the row starts new with zero attempts and carries the full
// position/reason/hash attribution; empty required fields are rejected.
func TestNewQuarantine(t *testing.T) {
	q, err := NewQuarantine("q1", "src1", "run1", "raw1", "line 12", "parse_error: missing cve_id", "aabb")
	if err != nil {
		t.Fatalf("NewQuarantine: unexpected error: %v", err)
	}
	if q.Status != QuarantineStatusNew || q.Attempts != 0 {
		t.Errorf("NewQuarantine = status %s attempts %d, want new with 0 attempts", q.Status, q.Attempts)
	}
	if q.ID != "q1" || q.SourceID != "src1" || q.SourceRunID != "run1" || q.RawRecordID != "raw1" {
		t.Errorf("NewQuarantine attribution not carried: %+v", q)
	}
	if q.Position != "line 12" || q.Reason != "parse_error: missing cve_id" || q.PayloadHash != "aabb" {
		t.Errorf("NewQuarantine failure info not carried: %+v", q)
	}

	// SourceRunID/RawRecordID are optional (attribution may come later).
	if _, err := NewQuarantine("q1", "src1", "", "", "p", "r", "h"); err != nil {
		t.Errorf("NewQuarantine without run/raw attribution: unexpected error: %v", err)
	}

	for _, tc := range []struct {
		name  string
		id    string
		src   string
		pos   string
		reas  string
		hash  string
		field string
	}{
		{"empty id", "", "src1", "p", "r", "h", "id"},
		{"empty source_id", "q1", "", "p", "r", "h", "source_id"},
		{"empty position", "q1", "src1", "", "r", "h", "position"},
		{"empty reason", "q1", "src1", "p", "", "h", "reason"},
		{"empty payload_hash", "q1", "src1", "p", "r", "", "payload_hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewQuarantine(tc.id, tc.src, "run1", "raw1", tc.pos, tc.reas, tc.hash); err == nil {
				t.Fatalf("want error for empty %s, got nil", tc.field)
			}
		})
	}
}

// newQuarantineIn builds a quarantine row in the requested status by
// walking the legal transitions from new — this doubles as a reachability
// proof for every non-terminal state of ARCH-002 §4.
func newQuarantineIn(t *testing.T, status QuarantineStatus) Quarantine {
	t.Helper()
	q, err := NewQuarantine("q1", "src1", "run1", "raw1", "line 12", "parse_error", "hash1")
	if err != nil {
		t.Fatalf("NewQuarantine: unexpected error: %v", err)
	}
	switch status {
	case QuarantineStatusNew:
		return q
	case QuarantineStatusAcknowledged:
		q, err = q.Acknowledge("ops-1", "reviewed: fixture outdated")
	case QuarantineStatusReadyForRetry:
		q, err = q.MarkReadyForRetry()
	case QuarantineStatusResolved:
		q, err = q.ReprocessSucceeded("v1", "e1", "")
	}
	if err != nil {
		t.Fatalf("cannot reach status %s: %v", status, err)
	}
	if q.Status != status {
		t.Fatalf("reached %s, want %s", q.Status, status)
	}
	return q
}

// TestQuarantineTransitions walks every allowed transition of the ARCH-002
// §4 state machine and asserts the resulting status plus the side effects
// each transition carries (acknowledgement attribution, result links,
// attempt counter).
func TestQuarantineTransitions(t *testing.T) {
	// Acknowledge: new → acknowledged, carries reviewer and note.
	q := newQuarantineIn(t, QuarantineStatusNew)
	got, err := q.Acknowledge("ops-1", "reviewed: fixture outdated")
	if err != nil {
		t.Fatalf("Acknowledge: unexpected error: %v", err)
	}
	if got.Status != QuarantineStatusAcknowledged {
		t.Errorf("Acknowledge: status = %s, want acknowledged", got.Status)
	}
	if got.AcknowledgedBy != "ops-1" || got.AcknowledgedNote != "reviewed: fixture outdated" {
		t.Errorf("Acknowledge: attribution not recorded: %+v", got)
	}
	if got.Attempts != 0 {
		t.Errorf("Acknowledge: attempts changed to %d, want 0", got.Attempts)
	}

	// MarkReadyForRetry: new → ready_for_retry and acknowledged →
	// ready_for_retry.
	for _, from := range []QuarantineStatus{QuarantineStatusNew, QuarantineStatusAcknowledged} {
		start := newQuarantineIn(t, from)
		got, err := start.MarkReadyForRetry()
		if err != nil {
			t.Fatalf("MarkReadyForRetry from %s: unexpected error: %v", from, err)
		}
		if got.Status != QuarantineStatusReadyForRetry {
			t.Errorf("MarkReadyForRetry from %s: status = %s, want ready_for_retry", from, got.Status)
		}
	}

	// ReprocessSucceeded: new → resolved and ready_for_retry → resolved,
	// linking the new domain object.
	for _, from := range []QuarantineStatus{QuarantineStatusNew, QuarantineStatusReadyForRetry} {
		start := newQuarantineIn(t, from)
		got, err := start.ReprocessSucceeded("v9", "e9", "reprocessed with nvd-normalizer-v2")
		if err != nil {
			t.Fatalf("ReprocessSucceeded from %s: unexpected error: %v", from, err)
		}
		if got.Status != QuarantineStatusResolved {
			t.Errorf("ReprocessSucceeded from %s: status = %s, want resolved", from, got.Status)
		}
		if got.ResolvedVulnerabilityID != "v9" || got.ResolvedEvidenceID != "e9" || got.ResolvedNote != "reprocessed with nvd-normalizer-v2" {
			t.Errorf("ReprocessSucceeded from %s: result not carried: %+v", from, got)
		}
	}

	// ReprocessFailed: attempts++ and the record stays retryable in the
	// state it was in (ARCH-002 §4: "stays retryable").
	for _, from := range []QuarantineStatus{QuarantineStatusNew, QuarantineStatusReadyForRetry} {
		start := newQuarantineIn(t, from)
		got, err := start.ReprocessFailed()
		if err != nil {
			t.Fatalf("ReprocessFailed from %s: unexpected error: %v", from, err)
		}
		if got.Status != from {
			t.Errorf("ReprocessFailed from %s: status = %s, want %s (stays retryable)", from, got.Status, from)
		}
		if got.Attempts != 1 {
			t.Errorf("ReprocessFailed from %s: attempts = %d, want 1", from, got.Attempts)
		}
		// The record stays retryable: a second attempt increments again.
		again, err := got.ReprocessFailed()
		if err != nil {
			t.Fatalf("ReprocessFailed twice from %s: unexpected error: %v", from, err)
		}
		if again.Attempts != 2 {
			t.Errorf("ReprocessFailed twice from %s: attempts = %d, want 2", from, again.Attempts)
		}
	}
}

// TestQuarantineNoInvalidTransition pins the guards: for every status and
// every transition the machine does not allow, the call must error — the
// invalid pairs of ARCH-002 §4 are not representable.
func TestQuarantineNoInvalidTransition(t *testing.T) {
	// transition under test → the statuses it must reject.
	guards := map[string][]QuarantineStatus{
		"Acknowledge":        {QuarantineStatusAcknowledged, QuarantineStatusReadyForRetry, QuarantineStatusResolved},
		"MarkReadyForRetry":  {QuarantineStatusReadyForRetry, QuarantineStatusResolved},
		"ReprocessSucceeded": {QuarantineStatusAcknowledged, QuarantineStatusResolved},
		"ReprocessFailed":    {QuarantineStatusAcknowledged, QuarantineStatusResolved},
	}
	for name, rejected := range guards {
		for _, status := range rejected {
			q := newQuarantineIn(t, status)
			var err error
			switch name {
			case "Acknowledge":
				_, err = q.Acknowledge("ops-1", "note")
			case "MarkReadyForRetry":
				_, err = q.MarkReadyForRetry()
			case "ReprocessSucceeded":
				_, err = q.ReprocessSucceeded("v1", "", "")
			case "ReprocessFailed":
				_, err = q.ReprocessFailed()
			}
			if err == nil {
				t.Errorf("%s from %s: want error, got nil", name, status)
				continue
			}
			if !strings.Contains(err.Error(), "domain:") {
				t.Errorf("%s from %s: error %v, want a domain error", name, status, err)
			}
			// A rejected transition must leave the row untouched.
			if q.Status != status {
				t.Errorf("%s from %s: row mutated to %s on rejection", name, status, q.Status)
			}
		}
	}
}

// TestQuarantineResolvedIsTerminal asserts that no transition leaves the
// resolved state: the machine has exactly one terminal status.
func TestQuarantineResolvedIsTerminal(t *testing.T) {
	q := newQuarantineIn(t, QuarantineStatusResolved)
	if _, err := q.Acknowledge("ops-1", "note"); err == nil {
		t.Error("Acknowledge on resolved: want error, got nil")
	}
	if _, err := q.MarkReadyForRetry(); err == nil {
		t.Error("MarkReadyForRetry on resolved: want error, got nil")
	}
	if _, err := q.ReprocessSucceeded("v1", "", ""); err == nil {
		t.Error("ReprocessSucceeded on resolved: want error, got nil")
	}
	if _, err := q.ReprocessFailed(); err == nil {
		t.Error("ReprocessFailed on resolved: want error, got nil")
	}
}

// TestQuarantineCommandGuards covers the parameter-level guards of the
// transitions: an acknowledgement needs a reviewer, a resolution must link
// the new domain object or carry a note.
func TestQuarantineCommandGuards(t *testing.T) {
	q := newQuarantineIn(t, QuarantineStatusNew)
	if _, err := q.Acknowledge("", "note"); err == nil {
		t.Error("Acknowledge without reviewer: want error, got nil")
	}

	ready := newQuarantineIn(t, QuarantineStatusReadyForRetry)
	if _, err := ready.ReprocessSucceeded("", "", ""); err == nil {
		t.Error("ReprocessSucceeded without result: want error, got nil")
	}
	// A justified discard resolves with a note and no link (ch. 8.6).
	if _, err := ready.ReprocessSucceeded("", "", "discarded: duplicate of CVE-2026-0002"); err != nil {
		t.Errorf("ReprocessSucceeded with note only: unexpected error: %v", err)
	}
}
