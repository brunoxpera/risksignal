package application

import (
	"testing"

	"github.com/xpera/risksignal/internal/domain"
)

// White-box tests of the run helpers (they exercise unexported code, so
// this file is part of the application package itself while the behavioural
// tests in *_test.go run against the exported surface in application_test).

// TestAffectedVersionMethod pins the minimal I1b matcher decision
// (ARCH-001 §3): exact equality is an exact_identifier, a dotted-prefix
// range (2.4 covers 2.4.4) a canonical_product_range, anything else no
// match.
func TestAffectedVersionMethod(t *testing.T) {
	tests := []struct {
		component string
		affected  string
		want      domain.MatchMethod
		matched   bool
	}{
		{"2.4.4", "2.4.4", domain.MatchMethodExactIdentifier, true},
		{"2.4.4", "2.4", domain.MatchMethodCanonicalProductRange, true},
		{"2.4.0", "2.4", domain.MatchMethodCanonicalProductRange, true},
		{"1.0.3", "1.0", domain.MatchMethodCanonicalProductRange, true},
		{"2.4.4", "2.5", "", false},
		{"2.4", "2.4.4", "", false}, // the range direction is source → component
		{"2.4.4", "", "", false},
		{"", "2.4", "", false},
		{" 2.4.4 ", "2.4", domain.MatchMethodCanonicalProductRange, true}, // versions are trimmed
	}
	for _, tt := range tests {
		got, ok := affectedVersionMethod(tt.component, tt.affected)
		if ok != tt.matched || got != tt.want {
			t.Errorf("affectedVersionMethod(%q, %q) = %q/%v, want %q/%v", tt.component, tt.affected, got, ok, tt.want, tt.matched)
		}
	}
}

// TestSignalDedupeKeyFormat pins the ARCH-001 §2 dedupe key shape.
func TestSignalDedupeKeyFormat(t *testing.T) {
	if got := signalDedupeKey("sig-1"); got != "signal.created:sig-1" {
		t.Errorf("signalDedupeKey = %q, want signal.created:sig-1", got)
	}
}
