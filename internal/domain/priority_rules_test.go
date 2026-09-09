package domain

import "testing"

// TestPriorityRuleVersion pins the hard-coded priority-rule version tag that
// is stored on every signal row (ARCH-001 §1 risk_signals.rule_version).
func TestPriorityRuleVersion(t *testing.T) {
	if PriorityRuleVersion != "i1b-1" {
		t.Errorf("PriorityRuleVersion = %q, want %q", PriorityRuleVersion, "i1b-1")
	}
}

// TestComputePriority covers every P1–P4 branch of the ch. 9.3 rules,
// including the P2 medium+KEV+context case and the P4 informational case.
// Case labels mirror the ARCH-001 §3 reference fixture (C1..C6) where
// applicable; the fixture's "expected priority" column is the oracle.
func TestComputePriority(t *testing.T) {
	tests := []struct {
		name        string
		conf        Confidence
		kev         bool
		cvss        float64
		epss        float64
		criticality Criticality
		exposure    Exposure
		want        Priority
	}{
		// P1: confidence high AND KEV AND critical/high or internet context.
		{"P1 high+kev+criticality critical (C1)", ConfidenceHigh, true, 9.8, 0.99, CriticalityCritical, ExposureInternet, PriorityP1},
		{"P1 high+kev+criticality high", ConfidenceHigh, true, 0, 0, CriticalityHigh, ExposureInternal, PriorityP1},
		{"P1 high+kev+exposure internet", ConfidenceHigh, true, 0, 0, CriticalityNormal, ExposureInternet, PriorityP1},

		// P2: confidence high with at least one urgency indicator.
		{"P2 high+kev without P1 context (C3)", ConfidenceHigh, true, 8.1, 0.97, CriticalityNormal, ExposureInternal, PriorityP2},
		{"P2 high+kev+unknown context", ConfidenceHigh, true, 0, 0, CriticalityUnknown, ExposureUnknown, PriorityP2},
		{"P2 high+cvss 9.0 threshold", ConfidenceHigh, false, 9.0, 0, CriticalityNormal, ExposureInternal, PriorityP2},
		{"P2 high+cvss 9.6 (C2)", ConfidenceHigh, false, 9.6, 0.90, CriticalityCritical, ExposureInternet, PriorityP2},
		{"P2 high+epss 0.95 threshold", ConfidenceHigh, false, 0, 0.95, CriticalityNormal, ExposureInternal, PriorityP2},

		// P2: confidence medium AND KEV AND critical/exposed context — the
		// medium+KEV+context branch of ch. 9.3.
		{"P2 medium+kev+criticality critical", ConfidenceMedium, true, 0, 0, CriticalityCritical, ExposureInternal, PriorityP2},
		{"P2 medium+kev+exposure internet", ConfidenceMedium, true, 0, 0, CriticalityLow, ExposureInternet, PriorityP2},

		// P3: plausible assignment without a strong urgency indicator.
		{"P3 high without urgency indicator (C4)", ConfidenceHigh, false, 7.2, 0.60, CriticalityNormal, ExposureInternal, PriorityP3},
		{"P3 high just below both thresholds", ConfidenceHigh, false, 8.9, 0.94, CriticalityCritical, ExposureInternet, PriorityP3},
		{"P3 medium without kev", ConfidenceMedium, false, 0, 0, CriticalityNormal, ExposureInternal, PriorityP3},
		{"P3 medium+kev without context", ConfidenceMedium, true, 0, 0, CriticalityNormal, ExposureInternal, PriorityP3},
		{"P3 medium+kev+unknown context", ConfidenceMedium, true, 0, 0, CriticalityUnknown, ExposureUnknown, PriorityP3},
		{"P3 medium with cvss/epss but no kev (ch 9.3 letter)", ConfidenceMedium, false, 9.9, 0.99, CriticalityCritical, ExposureInternet, PriorityP3},

		// P4: no confirmed inventory assignment / purely informational.
		{"P4 low candidate informational", ConfidenceLow, false, 0, 0, CriticalityNormal, ExposureInternal, PriorityP4},
		{"P4 low candidate even with strong factors", ConfidenceLow, true, 9.9, 0.99, CriticalityCritical, ExposureInternet, PriorityP4},
		{"P4 none no_match informational (C5)", ConfidenceNone, false, 5.0, 0.40, CriticalityLow, ExposureIsolated, PriorityP4},
		{"P4 none stays informational", ConfidenceNone, true, 10.0, 1.0, CriticalityHigh, ExposureInternet, PriorityP4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := PriorityFactors{
				Confidence:  tc.conf,
				KEV:         tc.kev,
				CVSS:        tc.cvss,
				EPSS:        tc.epss,
				Criticality: tc.criticality,
				Exposure:    tc.exposure,
			}
			if got := ComputePriority(f); got != tc.want {
				t.Errorf("ComputePriority(%+v) = %q, want %q", f, got, tc.want)
			}
		})
	}
}

// validFactors is a canonical, Validate-clean factor set used as the base for
// the validation tests below.
func validFactors() PriorityFactors {
	return PriorityFactors{
		Method:      MatchMethodCanonicalProductRange,
		Confidence:  ConfidenceHigh,
		KEV:         false,
		CVSS:        7.2,
		EPSS:        0.60,
		Criticality: CriticalityNormal,
		Exposure:    ExposureInternal,
	}
}

// TestPriorityFactorsValidate covers the accepted shapes (including candidate
// and no_match) and every rejected invariant.
func TestPriorityFactorsValidate(t *testing.T) {
	if err := validFactors().Validate(); err != nil {
		t.Fatalf("Validate on clean factors: unexpected error: %v", err)
	}

	accepted := []PriorityFactors{
		validFactors(),
		{Method: MatchMethodCandidate, Confidence: ConfidenceLow, Criticality: CriticalityCritical, Exposure: ExposureInternet}, // no cvss/epss/kev factors present
		{Method: MatchMethodNoMatch, Confidence: ConfidenceNone, Criticality: CriticalityLow, Exposure: ExposureIsolated},
	}
	for _, f := range accepted {
		if err := f.Validate(); err != nil {
			t.Errorf("Validate(%+v): unexpected error: %v", f, err)
		}
	}

	rejected := []struct {
		name string
		f    PriorityFactors
	}{
		{"unknown method", PriorityFactors{Method: MatchMethod("purl"), Confidence: ConfidenceHigh, Criticality: CriticalityNormal, Exposure: ExposureInternal}},
		{"confidence not derived from method", PriorityFactors{Method: MatchMethodNoMatch, Confidence: ConfidenceHigh, Criticality: CriticalityNormal, Exposure: ExposureInternal}},
		{"invalid confidence value", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: Confidence("maybe"), Criticality: CriticalityNormal, Exposure: ExposureInternal}},
		{"invalid criticality", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: ConfidenceHigh, Criticality: Criticality("severe"), Exposure: ExposureInternal}},
		{"invalid exposure", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: ConfidenceHigh, Criticality: CriticalityNormal, Exposure: Exposure("public")}},
		{"negative cvss", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: ConfidenceHigh, CVSS: -0.1, Criticality: CriticalityNormal, Exposure: ExposureInternal}},
		{"cvss above 10", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: ConfidenceHigh, CVSS: 10.1, Criticality: CriticalityNormal, Exposure: ExposureInternal}},
		{"negative epss", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: ConfidenceHigh, EPSS: -0.01, Criticality: CriticalityNormal, Exposure: ExposureInternal}},
		{"epss above 1", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: ConfidenceHigh, EPSS: 1.5, Criticality: CriticalityNormal, Exposure: ExposureInternal}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.f.Validate(); err == nil {
				t.Errorf("Validate(%+v): want error, got nil", tc.f)
			}
		})
	}
}

// TestNewRiskSignal verifies that the constructor derives the priority from
// the factors, defaults status to new with version 1, stamps the rule
// version, and rejects invalid factors or empty identities.
func TestNewRiskSignal(t *testing.T) {
	tests := []struct {
		name string
		f    PriorityFactors
		want Priority
	}{
		{"P1 from high+kev+critical", PriorityFactors{Method: MatchMethodExactIdentifier, Confidence: ConfidenceHigh, KEV: true, CVSS: 9.8, EPSS: 0.99, Criticality: CriticalityCritical, Exposure: ExposureInternet}, PriorityP1},
		{"P2 from medium+kev+context", PriorityFactors{Method: MatchMethodProductUncertainVersion, Confidence: ConfidenceMedium, KEV: true, Criticality: CriticalityHigh, Exposure: ExposureInternal}, PriorityP2},
		{"P4 from candidate", PriorityFactors{Method: MatchMethodCandidate, Confidence: ConfidenceLow, Criticality: CriticalityNormal, Exposure: ExposureInternal}, PriorityP4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewRiskSignal("s1", "m1", tc.f)
			if err != nil {
				t.Fatalf("NewRiskSignal: unexpected error: %v", err)
			}
			if s.ID != "s1" || s.MatchID != "m1" {
				t.Errorf("NewRiskSignal identities = %q/%q, want s1/m1", s.ID, s.MatchID)
			}
			if s.Priority != tc.want {
				t.Errorf("NewRiskSignal priority = %q, want %q", s.Priority, tc.want)
			}
			if s.Status != SignalStatusNew {
				t.Errorf("NewRiskSignal status = %q, want new", s.Status)
			}
			if s.Version != 1 {
				t.Errorf("NewRiskSignal version = %d, want 1", s.Version)
			}
			if s.RuleVersion != PriorityRuleVersion {
				t.Errorf("NewRiskSignal rule_version = %q, want %q", s.RuleVersion, PriorityRuleVersion)
			}
			if s.Factors != tc.f {
				t.Errorf("NewRiskSignal factors = %+v, want %+v", s.Factors, tc.f)
			}
			if s.Owner != "" {
				t.Errorf("NewRiskSignal owner = %q, want empty", s.Owner)
			}
		})
	}

	if _, err := NewRiskSignal("", "m1", validFactors()); err == nil {
		t.Error("NewRiskSignal with empty id: want error, got nil")
	}
	if _, err := NewRiskSignal("s1", "", validFactors()); err == nil {
		t.Error("NewRiskSignal with empty match_id: want error, got nil")
	}
	bad := validFactors()
	bad.Confidence = ConfidenceNone // method still canonical_product_range → mismatch
	if _, err := NewRiskSignal("s1", "m1", bad); err == nil {
		t.Error("NewRiskSignal with method/confidence mismatch: want error, got nil")
	}
}
