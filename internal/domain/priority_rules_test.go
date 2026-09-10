package domain

import "testing"

// priorityCell is one reference cell of the ch. 9.3 priority matrix. It is
// the oracle shared by the I1b ComputePriority test and the seeded-ruleset
// reproduction test.
type priorityCell struct {
	name        string
	conf        Confidence
	kev         bool
	cvss        float64
	epss        float64
	criticality Criticality
	exposure    Exposure
	want        Priority
}

// priorityMatrix is the ARCH-001 §3 reference fixture (C1..C6) covering
// every P1–P4 branch of the ch. 9.3 rules, including the P2 medium+KEV
// context case and the P4 informational case.
func priorityMatrix() []priorityCell {
	return []priorityCell{
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
}

func (c priorityCell) factors() PriorityFactors {
	return PriorityFactors{
		Confidence:  c.conf,
		KEV:         c.kev,
		CVSS:        c.cvss,
		EPSS:        c.epss,
		Criticality: c.criticality,
		Exposure:    c.exposure,
	}
}

// TestPriorityRuleVersionI1b pins the legacy I1b tag, kept valid as history.
func TestPriorityRuleVersionI1b(t *testing.T) {
	if PriorityRuleVersionI1b != "i1b-1" {
		t.Errorf("PriorityRuleVersionI1b = %q, want %q", PriorityRuleVersionI1b, "i1b-1")
	}
}

// TestPriorityRuleVersion covers the zero-padded "p%010d" mapping, the
// monotone text ordering implied by the padding, and the error on a
// non-positive version.
func TestPriorityRuleVersion(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{1, "p0000000001"},
		{2, "p0000000002"},
		{10, "p0000000010"},
		{2, "p0000000002"},
	}
	for _, tc := range tests {
		got, err := PriorityRuleVersion(tc.n)
		if err != nil {
			t.Fatalf("PriorityRuleVersion(%d): unexpected error: %v", tc.n, err)
		}
		if got != tc.want {
			t.Errorf("PriorityRuleVersion(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
	// Zero-padding makes text order follow numeric order across a digit
	// boundary: "p...10" sorts above "p...2".
	two, _ := PriorityRuleVersion(2)
	ten, _ := PriorityRuleVersion(10)
	if ten <= two {
		t.Errorf("padded versions out of order: %q must sort above %q", ten, two)
	}
	for _, n := range []int{0, -1, -42} {
		if _, err := PriorityRuleVersion(n); err == nil {
			t.Errorf("PriorityRuleVersion(%d): want error, got nil", n)
		}
	}
}

// TestSeedPriorityRulesValid pins the seeded ruleset shape: the four ch. 9.3
// rules, enabled, at the seed version, each value-valid.
func TestSeedPriorityRulesValid(t *testing.T) {
	rules := SeedPriorityRules()
	if len(rules) != 4 {
		t.Fatalf("SeedPriorityRules len = %d, want 4", len(rules))
	}
	wantOrder := []Priority{PriorityP1, PriorityP2, PriorityP3, PriorityP4}
	for i, r := range rules {
		if r.RuleID != wantOrder[i] {
			t.Errorf("rule %d = %s, want %s", i, r.RuleID, wantOrder[i])
		}
		if r.Version != SeedPriorityRulesVersion {
			t.Errorf("rule %s version = %d, want %d", r.RuleID, r.Version, SeedPriorityRulesVersion)
		}
		if !r.Enabled {
			t.Errorf("rule %s is disabled, want enabled", r.RuleID)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("rule %s Validate: unexpected error: %v", r.RuleID, err)
		}
	}
}

// TestComputePriority covers the ch. 9.3 matrix through the I1b
// compatibility entry point (unchanged behaviour).
func TestComputePriority(t *testing.T) {
	for _, tc := range priorityMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.factors()
			if got := ComputePriority(f); got != tc.want {
				t.Errorf("ComputePriority(%+v) = %q, want %q", f, got, tc.want)
			}
		})
	}
}

// TestSeedRulesReproduceComputePriority is the behaviour-preserving proof:
// the seeded ruleset v1, evaluated first-match-wins, reproduces the I1b
// ComputePriority outputs for every reference cell.
func TestSeedRulesReproduceComputePriority(t *testing.T) {
	rules := SeedPriorityRules()
	for _, tc := range priorityMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.factors()
			got, err := EvaluatePriority(rules, f)
			if err != nil {
				t.Fatalf("EvaluatePriority: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("EvaluatePriority(seed, %+v) = %q, want %q", f, got, tc.want)
			}
			if got != ComputePriority(f) {
				t.Errorf("seed EvaluatePriority(%+v) = %q, ComputePriority = %q (divergence)", f, got, ComputePriority(f))
			}
		})
	}
}

// TestSeedReproductionProperty is a bounded property test: over a grid of
// every confidence × kev × {below/at/above threshold cvss/epss} × every
// criticality × every exposure, the seed ruleset and ComputePriority agree.
func TestSeedReproductionProperty(t *testing.T) {
	confs := []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceNone}
	kevs := []bool{false, true}
	cvss := []float64{0, 8.9, 9.0, 9.6, 10}
	epss := []float64{0, 0.94, 0.95, 0.99, 1}
	crits := []Criticality{CriticalityCritical, CriticalityHigh, CriticalityNormal, CriticalityLow, CriticalityUnknown}
	exps := []Exposure{ExposureInternet, ExposureInternal, ExposureIsolated, ExposureUnknown}

	rules := SeedPriorityRules()
	for _, conf := range confs {
		for _, kev := range kevs {
			for _, c := range cvss {
				for _, e := range epss {
					for _, crit := range crits {
						for _, exp := range exps {
							f := PriorityFactors{Confidence: conf, KEV: kev, CVSS: c, EPSS: e, Criticality: crit, Exposure: exp}
							seed, err := EvaluatePriority(rules, f)
							if err != nil {
								t.Fatalf("EvaluatePriority(%+v): unexpected error: %v", f, err)
							}
							if seed != ComputePriority(f) {
								t.Fatalf("seed(%+v) = %q, ComputePriority = %q", f, seed, ComputePriority(f))
							}
						}
					}
				}
			}
		}
	}
}

// TestEvaluatePriorityDisabledAndTerminal pins the terminal-P4 and
// disabled-rule semantics: a disabled higher rule demotes to the next match,
// and an empty/partial ruleset falls back to P4.
func TestEvaluatePriorityDisabledAndTerminal(t *testing.T) {
	rules := SeedPriorityRules()
	// Disable P1: a P1 cell demotes to the next matching rule (P2).
	rules[0] = rules[0].Disable()
	p1 := priorityCell{conf: ConfidenceHigh, kev: true, criticality: CriticalityCritical, exposure: ExposureInternet}
	got, err := EvaluatePriority(rules, p1.factors())
	if err != nil {
		t.Fatalf("EvaluatePriority: %v", err)
	}
	if got != PriorityP2 {
		t.Errorf("P1 disabled on a P1 cell = %q, want P2 (demote)", got)
	}

	// Empty ruleset: terminal P4, never an error.
	if got, err := EvaluatePriority(nil, p1.factors()); err != nil || got != PriorityP4 {
		t.Errorf("EvaluatePriority(nil) = %q/%v, want P4/nil", got, err)
	}
}

// TestEvaluatePriorityErrorsOnBadDefinition: a malformed rule surfaces the
// evaluator error rather than a silent non-match.
func TestEvaluatePriorityErrorsOnBadDefinition(t *testing.T) {
	rules := []PriorityRule{{
		RuleID:     PriorityP1,
		Version:    SeedPriorityRulesVersion,
		Enabled:    true,
		ActorID:    "system",
		Definition: RuleDefinition{Op: RuleOp("~="), Field: FieldConfidence, Values: []string{"high"}},
	}}
	if _, err := EvaluatePriority(rules, PriorityFactors{Confidence: ConfidenceHigh}); err == nil {
		t.Error("EvaluatePriority with an unknown op: want error, got nil")
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
// the factors, defaults status to new with version 1, stamps the legacy rule
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
			if s.RuleVersion != PriorityRuleVersionI1b {
				t.Errorf("NewRiskSignal rule_version = %q, want %q", s.RuleVersion, PriorityRuleVersionI1b)
			}
			if s.Factors != tc.f {
				t.Errorf("NewRiskSignal factors = %+v, want %+v", s.Factors, tc.f)
			}
			if s.Owner != "" {
				t.Errorf("NewRiskSignal owner = %q, want empty", s.Owner)
			}
			if s.Overridden() {
				t.Error("NewRiskSignal must not start overridden")
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

// TestNewPriorityRule covers the value-object invariants.
func TestNewPriorityRule(t *testing.T) {
	def := RuleDefinition{AllOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldConfidence, Values: []string{"high"}},
	}}
	r, err := NewPriorityRule(PriorityP1, 1, def, "why", "actor")
	if err != nil {
		t.Fatalf("NewPriorityRule: unexpected error: %v", err)
	}
	if !r.Enabled {
		t.Error("a new rule must be enabled")
	}
	if err := r.Validate(); err != nil {
		t.Errorf("Validate: unexpected error: %v", err)
	}
	if r.Disable().Enabled {
		t.Error("Disable must clear Enabled")
	}
	if !r.Disable().Enable().Enabled {
		t.Error("Enable must set Enabled")
	}

	rejected := []struct {
		name    string
		id      Priority
		version int
		def     RuleDefinition
		actor   string
	}{
		{"invalid rule id", Priority("P9"), 1, def, "actor"},
		{"non-positive version", PriorityP1, 0, def, "actor"},
		{"empty actor", PriorityP1, 1, def, ""},
		{"empty definition", PriorityP1, 1, RuleDefinition{}, "actor"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPriorityRule(tc.id, tc.version, tc.def, "", tc.actor); err == nil {
				t.Errorf("NewPriorityRule(%s): want error, got nil", tc.name)
			}
		})
	}
}
