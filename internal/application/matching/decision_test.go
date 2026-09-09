package matching_test

// Decision-rule tests of the matching engine (ARCH-003 §3, ADR-015):
// exclude rules force a visible no_match that references the rule,
// override rules force the action while the raw computed triple is
// preserved in auto_*, reasons stay auditable and the applicability is
// evaluated against the (cve, component) pair and the injected clock
// instant. The expected field semantics mirror the domain-level
// ApplyDecisionRule tests (internal/domain/rules_test.go).

import (
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application/matching"
	"github.com/xpera/risksignal/internal/domain"
)

// decisionFixture is one exclude/override test: a raw canonical-product
// match (high/80) with a decision rule applied on top.
func decisionFixture(t *testing.T) (matching.Input, matching.Outcome) {
	t.Helper()
	comp := fixtureComponent("comp-dr", domain.ComponentIdentifiers{
		Vendor:  "acme",
		Product: "widget",
		Version: "1.5.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	// Read the raw outcome first (no decision rules), so the tests can
	// assert the auto_* preservation against the true computed triple.
	rawIn := matching.Input{
		CVEID:      "CVE-2026-0001",
		Statements: []matching.AffectedProduct{{Vendor: "acme", Product: "widget", Ranges: []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}}}},
		Component:  comp,
	}
	raw, err := matching.Evaluate(rawIn)
	if err != nil {
		t.Fatalf("Evaluate(raw): unexpected error: %v", err)
	}
	if raw.Method != domain.MatchMethodCanonicalProductRange || raw.Confidence != domain.ConfidenceHigh || raw.Score != 80 {
		t.Fatalf("raw outcome = %s/%s/%d, want canonical_product_range/high/80", raw.Method, raw.Confidence, raw.Score)
	}
	return rawIn, raw
}

func mustDecisionRule(t *testing.T, typ domain.DecisionRuleType, target domain.DecisionTarget, action *domain.DecisionAction, version int) domain.DecisionRule {
	t.Helper()
	r, err := domain.NewDecisionRule("dr-"+string(typ), typ, target, action, "manual correction: fixture", "alice", version, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("NewDecisionRule: unexpected error: %v", err)
	}
	return r
}

// TestExcludeRuleForcesNoMatch: an applicable exclude rule emits a
// no_match outcome (none/0) that references the rule, keeps the computed
// reasons plus the exclusion note, and sets no auto_* triple — the
// exclusion is visible and auditable and only an override preserves the
// computed starting point.
func TestExcludeRuleForcesNoMatch(t *testing.T) {
	rawIn, raw := decisionFixture(t)
	rule := mustDecisionRule(t, domain.DecisionRuleTypeExclude, domain.DecisionTarget{CVEID: "CVE-2026-0001", Product: "widget"}, nil, 2)
	in := rawIn
	in.DecisionRules = []domain.DecisionRule{rule}
	in.Now = time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

	out, err := matching.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if out.Method != domain.MatchMethodNoMatch || out.Confidence != domain.ConfidenceNone || out.Score != 0 {
		t.Errorf("exclude outcome = %s/%s/%d, want no_match/none/0", out.Method, out.Confidence, out.Score)
	}
	if out.DecisionRuleID == nil || *out.DecisionRuleID != rule.ID {
		t.Errorf("exclude outcome DecisionRuleID = %v, want %q (the exclusion must reference the rule)", out.DecisionRuleID, rule.ID)
	}
	if out.AutoMethod != nil || out.AutoConfidence != nil || out.AutoScore != nil {
		t.Errorf("exclude outcome must not set auto_* (only an override preserves the raw triple)")
	}
	if len(out.Reasons) != len(raw.Reasons)+1 {
		t.Errorf("exclude reasons = %d entries, want the %d computed reasons plus the exclusion note", len(out.Reasons), len(raw.Reasons))
	}
	if last := out.Reasons[len(out.Reasons)-1]; last != "excluded by decision rule "+rule.ID+": manual correction: fixture" {
		t.Errorf("exclusion note = %q, want it to name the rule and its rationale", last)
	}
	if out.RuleVersion != raw.RuleVersion {
		t.Errorf("exclude RuleVersion = %q, want the computed %q", out.RuleVersion, raw.RuleVersion)
	}
}

// TestOverrideRuleForcesAction: an applicable override rule forces the
// action's method/confidence/score while the raw computed triple moves
// into auto_* — the computed starting point stays visible and the
// override stays reversible.
func TestOverrideRuleForcesAction(t *testing.T) {
	rawIn, _ := decisionFixture(t)
	rule := mustDecisionRule(t, domain.DecisionRuleTypeOverride,
		domain.DecisionTarget{CVEID: "CVE-2026-0001"},
		&domain.DecisionAction{Method: domain.MatchMethodProductUncertainVersion}, 2)
	in := rawIn
	in.DecisionRules = []domain.DecisionRule{rule}

	out, err := matching.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if out.Method != domain.MatchMethodProductUncertainVersion || out.Confidence != domain.ConfidenceMedium || out.Score != 65 {
		t.Errorf("override outcome = %s/%s/%d, want product_uncertain_version/medium/65", out.Method, out.Confidence, out.Score)
	}
	if out.DecisionRuleID == nil || *out.DecisionRuleID != rule.ID {
		t.Errorf("override outcome DecisionRuleID = %v, want %q", out.DecisionRuleID, rule.ID)
	}
	if out.AutoMethod == nil || *out.AutoMethod != domain.MatchMethodCanonicalProductRange ||
		out.AutoConfidence == nil || *out.AutoConfidence != domain.ConfidenceHigh ||
		out.AutoScore == nil || *out.AutoScore != 80 {
		t.Errorf("override auto_* = %v/%v/%v, want the raw canonical_product_range/high/80 triple",
			out.AutoMethod, out.AutoConfidence, out.AutoScore)
	}
	if last := out.Reasons[len(out.Reasons)-1]; last != "overridden by decision rule "+rule.ID+": manual correction: fixture" {
		t.Errorf("override note = %q, want it to name the rule and its rationale", last)
	}
	if out.Score == *out.AutoScore {
		t.Error("the effective score must differ from the preserved auto_score in this fixture")
	}
}

// TestOverrideToCandidateCarriesSimilarity: an override forcing candidate
// carries the manually supplied similarity as the score (the one case
// where the score is computed input, not a fixed rank).
func TestOverrideToCandidateCarriesSimilarity(t *testing.T) {
	rawIn, _ := decisionFixture(t)
	rule := mustDecisionRule(t, domain.DecisionRuleTypeOverride,
		domain.DecisionTarget{ComponentID: rawIn.Component.ID},
		&domain.DecisionAction{Method: domain.MatchMethodCandidate, Similarity: 42}, 2)
	in := rawIn
	in.DecisionRules = []domain.DecisionRule{rule}

	out, err := matching.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if out.Method != domain.MatchMethodCandidate || out.Confidence != domain.ConfidenceLow || out.Score != 42 {
		t.Errorf("candidate override outcome = %s/%s/%d, want candidate/low/42", out.Method, out.Confidence, out.Score)
	}
	if out.AutoScore == nil || *out.AutoScore != 80 {
		t.Errorf("candidate override auto_score = %v, want the raw 80", out.AutoScore)
	}
}

// TestDecisionRuleApplicability: a rule only applies when every set
// target field matches the pair and the rule is effective at the clock
// instant (revocation and the half-open validity window).
func TestDecisionRuleApplicability(t *testing.T) {
	rawIn, _ := decisionFixture(t)
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	exclude := mustDecisionRule(t, domain.DecisionRuleTypeExclude,
		domain.DecisionTarget{CVEID: "CVE-2026-0001", Vendor: "acme", Product: "widget", ComponentID: rawIn.Component.ID}, nil, 1)

	// Base: the full target matches — the rule applies.
	in := rawIn
	in.DecisionRules = []domain.DecisionRule{exclude}
	in.Now = now
	if out, err := matching.Evaluate(in); err != nil || out.Method != domain.MatchMethodNoMatch {
		t.Errorf("full-target rule: outcome = %v/%v, want no_match", out.Method, err)
	}

	// A differing CVE id keeps the rule out.
	other := in
	other.CVEID = "CVE-2026-9999"
	if out, err := matching.Evaluate(other); err != nil || out.Method == domain.MatchMethodNoMatch {
		t.Errorf("rule with a cve target must not apply to another cve (method = %v, err = %v)", out.Method, err)
	}

	// A different component (vendor/product/component_id all miss).
	mismatch := rawIn
	mismatch.Component = fixtureComponent("comp-other", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "gadget", Version: "1.0.0",
	}, "acme", "gadget", domain.VersionSchemeSemver)
	mismatch.DecisionRules = []domain.DecisionRule{exclude}
	mismatch.Now = now
	if out, err := matching.Evaluate(mismatch); err != nil || out.Method == domain.MatchMethodNoMatch {
		t.Errorf("rule with vendor/product/component targets must not apply to another component (method = %v, err = %v)", out.Method, err)
	}

	// Wildcard target fields: a rule scoped to the product alone applies
	// to any component of that product.
	wildcard := mustDecisionRule(t, domain.DecisionRuleTypeExclude, domain.DecisionTarget{Product: "widget"}, nil, 1)
	for _, comp := range []domain.Component{rawIn.Component, mismatch.Component} {
		in := rawIn
		in.Component = comp
		in.DecisionRules = []domain.DecisionRule{wildcard}
		in.Now = now
		var want domain.MatchMethod
		switch {
		case comp.Product == "widget":
			want = domain.MatchMethodNoMatch // the product-scoped exclusion applies
		case comp.Product == "gadget":
			want = domain.MatchMethodCandidate // unrelated product: no relation, rule not applicable
		}
		if out, err := matching.Evaluate(in); err != nil || out.Method != want {
			t.Errorf("product-scoped rule on %q: outcome = %v/%v, want %v", comp.Product, out.Method, err, want)
		}
	}

	// Revoked rules and expired windows are inert.
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	windowed, err := domain.NewDecisionRule("dr-window", domain.DecisionRuleTypeExclude,
		domain.DecisionTarget{Product: "widget"}, nil, "windowed", "alice", 1, from, until)
	if err != nil {
		t.Fatalf("NewDecisionRule(windowed): unexpected error: %v", err)
	}
	revoked, err := windowed.Revoke()
	if err != nil {
		t.Fatalf("Revoke: unexpected error: %v", err)
	}
	for _, tc := range []struct {
		name string
		rule domain.DecisionRule
		now  time.Time
	}{
		{"expired window", windowed, now}, // now is after valid_until
		{"not yet valid", windowed, from.Add(-time.Hour)},
		{"revoked", revoked, from.Add(time.Hour)}, // inside the window but revoked
	} {
		in := rawIn
		in.DecisionRules = []domain.DecisionRule{tc.rule}
		in.Now = tc.now
		if out, err := matching.Evaluate(in); err != nil || out.Method != domain.MatchMethodCanonicalProductRange {
			t.Errorf("%s: rule must be inert (method = %v, err = %v)", tc.name, out.Method, err)
		}
	}
	// Inside the window and not revoked: the rule applies.
	in = rawIn
	in.DecisionRules = []domain.DecisionRule{windowed}
	in.Now = from.Add(time.Hour)
	if out, err := matching.Evaluate(in); err != nil || out.Method != domain.MatchMethodNoMatch {
		t.Errorf("rule inside its window: outcome = %v/%v, want no_match", out.Method, err)
	}
}

// TestFirstApplicableRuleWins: conflicting rules resolve deterministically
// — the rules are ordered by (version, id) and the first applicable rule
// wins; the outcome is the same whatever the input order.
func TestFirstApplicableRuleWins(t *testing.T) {
	rawIn, _ := decisionFixture(t)
	exclude := mustDecisionRule(t, domain.DecisionRuleTypeExclude, domain.DecisionTarget{Product: "widget"}, nil, 1)
	override := mustDecisionRule(t, domain.DecisionRuleTypeOverride,
		domain.DecisionTarget{Product: "widget"},
		&domain.DecisionAction{Method: domain.MatchMethodProductUncertainVersion}, 2)

	for _, rules := range [][]domain.DecisionRule{{exclude, override}, {override, exclude}} {
		in := rawIn
		in.DecisionRules = rules
		out, err := matching.Evaluate(in)
		if err != nil {
			t.Fatalf("Evaluate: unexpected error: %v", err)
		}
		// version 1 (exclude) sorts first: the exclusion wins.
		if out.Method != domain.MatchMethodNoMatch || out.DecisionRuleID == nil || *out.DecisionRuleID != exclude.ID {
			t.Errorf("conflicting rules: outcome = %s (rule %v), want the exclude of version 1", out.Method, out.DecisionRuleID)
		}
	}
}

// TestDecisionRuleOnNoMatch: an exclusion applied to an already-computed
// no_match keeps the no_match outcome and references the rule.
func TestDecisionRuleOnNoMatch(t *testing.T) {
	comp := fixtureComponent("comp-none-dr", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "3.0.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	rawIn := matching.Input{
		CVEID:      "CVE-2026-0001",
		Statements: []matching.AffectedProduct{{Vendor: "acme", Product: "widget", Ranges: []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}}}},
		Component:  comp,
	}
	rule := mustDecisionRule(t, domain.DecisionRuleTypeExclude, domain.DecisionTarget{ComponentID: comp.ID}, nil, 1)
	in := rawIn
	in.DecisionRules = []domain.DecisionRule{rule}
	out, err := matching.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if out.Method != domain.MatchMethodNoMatch || out.Score != 0 {
		t.Errorf("excluded no_match outcome = %s/%d, want no_match/0", out.Method, out.Score)
	}
	if out.DecisionRuleID == nil || *out.DecisionRuleID != rule.ID {
		t.Errorf("DecisionRuleID = %v, want the excluding rule", out.DecisionRuleID)
	}
}

// TestRuleVersionStampedOnOutcome: every outcome carries the composite
// ruleset version derived from the input counters (zero-padded so
// multi-digit rule versions order correctly, DEV-057).
func TestRuleVersionStampedOnOutcome(t *testing.T) {
	rawIn, raw := decisionFixture(t)
	in := rawIn
	in.AliasVersion = 3
	in.DecisionVersion = 2
	out, err := matching.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if want := "a0000000003d0000000002"; out.RuleVersion != want {
		t.Errorf("RuleVersion = %q, want %q", out.RuleVersion, want)
	}
	if raw.RuleVersion == out.RuleVersion {
		t.Error("the raw fixture (0/0) and the stamped outcome must differ in rule version")
	}
}
