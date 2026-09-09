package domain

import "testing"

// TestMatchRuleVersion pins the hard-coded mapping version tag that is
// stored on every match row (ARCH-001 §1 matches.rule_version).
func TestMatchRuleVersion(t *testing.T) {
	if MatchRuleVersion != "i1b-1" {
		t.Errorf("MatchRuleVersion = %q, want %q", MatchRuleVersion, "i1b-1")
	}
}

// TestDeriveMatchMapping covers the full ADR-015 method→confidence/score
// table (ch. 9.2): every deterministic method maps to its fixed rank, and
// candidate maps to low with the caller-supplied computed similarity.
func TestDeriveMatchMapping(t *testing.T) {
	tests := []struct {
		name       string
		method     MatchMethod
		similarity int
		wantConf   Confidence
		wantScore  int
	}{
		{"exact_identifier", MatchMethodExactIdentifier, 0, ConfidenceHigh, 100},
		{"container_digest", MatchMethodContainerDigest, 0, ConfidenceHigh, 95},
		{"alias_exact_version", MatchMethodAliasExactVersion, 0, ConfidenceHigh, 90},
		{"canonical_product_range", MatchMethodCanonicalProductRange, 0, ConfidenceHigh, 80},
		{"product_uncertain_version", MatchMethodProductUncertainVersion, 0, ConfidenceMedium, 65},
		{"controlled_alias_only", MatchMethodControlledAliasOnly, 0, ConfidenceMedium, 55},
		{"candidate similarity 1", MatchMethodCandidate, 1, ConfidenceLow, 1},
		{"candidate similarity 27", MatchMethodCandidate, 27, ConfidenceLow, 27},
		{"candidate similarity 54", MatchMethodCandidate, 54, ConfidenceLow, 54},
		{"no_match", MatchMethodNoMatch, 0, ConfidenceNone, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf, score, err := tc.method.Derive(tc.similarity)
			if err != nil {
				t.Fatalf("Derive(%d): unexpected error: %v", tc.similarity, err)
			}
			if conf != tc.wantConf {
				t.Errorf("Derive confidence = %q, want %q", conf, tc.wantConf)
			}
			if score != tc.wantScore {
				t.Errorf("Derive score = %d, want %d", score, tc.wantScore)
			}
		})
	}
}

// TestDeriveMatchInvalid covers invalid handling of the ADR-015 mapping:
// unknown methods and candidate similarities outside the 1–54 band error
// instead of silently deriving a value.
func TestDeriveMatchInvalid(t *testing.T) {
	if _, _, err := MatchMethod("purl").Derive(0); err == nil {
		t.Error("Derive on unknown method: want error, got nil")
	}
	if _, _, err := MatchMethod("").Derive(0); err == nil {
		t.Error("Derive on empty method: want error, got nil")
	}
	for _, s := range []int{0, -1, 55, 100} {
		if _, _, err := MatchMethodCandidate.Derive(s); err == nil {
			t.Errorf("Derive candidate with similarity %d: want error, got nil", s)
		}
	}
}

// TestMatchMethodConfidenceDerived checks the confidence half of the mapping
// for every method and the unknown-method guard of Confidence.
func TestMatchMethodConfidenceDerived(t *testing.T) {
	want := map[MatchMethod]Confidence{
		MatchMethodExactIdentifier:         ConfidenceHigh,
		MatchMethodContainerDigest:         ConfidenceHigh,
		MatchMethodAliasExactVersion:       ConfidenceHigh,
		MatchMethodCanonicalProductRange:   ConfidenceHigh,
		MatchMethodProductUncertainVersion: ConfidenceMedium,
		MatchMethodControlledAliasOnly:     ConfidenceMedium,
		MatchMethodCandidate:               ConfidenceLow,
		MatchMethodNoMatch:                 ConfidenceNone,
	}
	for method, wantConf := range want {
		conf, ok := method.Confidence()
		if !ok {
			t.Errorf("Confidence(%q): ok = false, want true", method)
			continue
		}
		if conf != wantConf {
			t.Errorf("Confidence(%q) = %q, want %q", method, conf, wantConf)
		}
	}
	if conf, ok := MatchMethod("purl").Confidence(); ok {
		t.Errorf("Confidence(unknown) = %q with ok = true, want false", conf)
	}
}

// TestNewMatchDerivesFromMethod verifies the constructor enforces the
// ADR-015 invariant: confidence, score and rule version follow from the
// method, and invalid input is rejected.
func TestNewMatchDerivesFromMethod(t *testing.T) {
	m, err := NewMatch("m1", "v1", "c1", MatchMethodExactIdentifier, 0)
	if err != nil {
		t.Fatalf("NewMatch(exact_identifier): unexpected error: %v", err)
	}
	if m.Confidence != ConfidenceHigh || m.Score != 100 || m.RuleVersion != MatchRuleVersion {
		t.Errorf("NewMatch(exact_identifier) = conf %q score %d rule %q, want high/100/%s",
			m.Confidence, m.Score, m.RuleVersion, MatchRuleVersion)
	}

	m, err = NewMatch("m2", "v1", "c1", MatchMethodCandidate, 42)
	if err != nil {
		t.Fatalf("NewMatch(candidate): unexpected error: %v", err)
	}
	if m.Confidence != ConfidenceLow || m.Score != 42 {
		t.Errorf("NewMatch(candidate) = conf %q score %d, want low/42", m.Confidence, m.Score)
	}

	if _, err := NewMatch("m3", "v1", "c1", MatchMethod("purl"), 0); err == nil {
		t.Error("NewMatch with unknown method: want error, got nil")
	}
	if _, err := NewMatch("m3", "v1", "c1", MatchMethodCandidate, 0); err == nil {
		t.Error("NewMatch candidate with out-of-range similarity: want error, got nil")
	}
	if _, err := NewMatch("", "v1", "c1", MatchMethodNoMatch, 0); err == nil {
		t.Error("NewMatch with empty id: want error, got nil")
	}
	if _, err := NewMatch("m3", "", "c1", MatchMethodNoMatch, 0); err == nil {
		t.Error("NewMatch with empty vulnerability_id: want error, got nil")
	}
	if _, err := NewMatch("m3", "v1", "", MatchMethodNoMatch, 0); err == nil {
		t.Error("NewMatch with empty component_id: want error, got nil")
	}
}
