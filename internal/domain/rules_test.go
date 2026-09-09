package domain

import (
	"testing"
	"time"
)

// Rule value objects, the ruleset-version derivation and the Match
// extension (ARCH-003 §1.4/§3, ADR-015): AliasRule/DecisionRule shape and
// validity, the AppliesAt window semantics, RulesetVersion "a<n>d<m>" and
// the exclude/override outcome stamped onto a raw computed match.

// TestParseAliasScope covers the alias scope vocabulary.
func TestParseAliasScope(t *testing.T) {
	for _, want := range []AliasScope{AliasScopeVendor, AliasScopeProduct} {
		got, err := ParseAliasScope(string(want))
		if err != nil || got != want || !want.Valid() {
			t.Errorf("ParseAliasScope(%q) = %q, %v; want %q without error", want, got, err, want)
		}
	}
	for _, s := range []string{"", "vendor ", "component", "Vendor"} {
		if _, err := ParseAliasScope(s); err == nil {
			t.Errorf("ParseAliasScope(%q): want error", s)
		}
	}
}

// TestAliasRule covers the alias rule value object and its validation.
func TestAliasRule(t *testing.T) {
	r, err := NewAliasRule("ar1", AliasScopeVendor, "sun microsystems", "oracle", "sun was acquired by oracle", 3)
	if err != nil {
		t.Fatalf("NewAliasRule: unexpected error: %v", err)
	}
	if r.ID != "ar1" || r.Scope != AliasScopeVendor || r.From != "sun microsystems" || r.To != "oracle" || r.Version != 3 || !r.Enabled {
		t.Errorf("NewAliasRule = %+v, want the supplied values and Enabled true", r)
	}

	if _, err := NewAliasRule("", AliasScopeVendor, "a", "b", "", 1); err == nil {
		t.Error("empty id: want error")
	}
	if _, err := NewAliasRule("x", AliasScope("component"), "a", "b", "", 1); err == nil {
		t.Error("invalid scope: want error")
	}
	if _, err := NewAliasRule("x", AliasScopeVendor, "", "b", "", 1); err == nil {
		t.Error("empty from: want error")
	}
	if _, err := NewAliasRule("x", AliasScopeVendor, "a", "", "", 1); err == nil {
		t.Error("empty to: want error")
	}
	if _, err := NewAliasRule("x", AliasScopeVendor, "a", "a", "", 1); err == nil {
		t.Error("self mapping: want error")
	}
	if _, err := NewAliasRule("x", AliasScopeVendor, "a", "b", "", 0); err == nil {
		t.Error("version 0: want error")
	}

	disabled := r.Disable()
	if disabled.Enabled || !r.Enabled {
		t.Error("Disable must return a disabled copy and leave the original enabled")
	}
	if re := disabled.Enable(); !re.Enabled {
		t.Error("Enable must return an enabled copy")
	}
}

// TestParseDecisionRuleType covers the decision rule type vocabulary.
func TestParseDecisionRuleType(t *testing.T) {
	for _, want := range []DecisionRuleType{DecisionRuleTypeExclude, DecisionRuleTypeOverride} {
		got, err := ParseDecisionRuleType(string(want))
		if err != nil || got != want || !want.Valid() {
			t.Errorf("ParseDecisionRuleType(%q) = %q, %v; want %q without error", want, got, err, want)
		}
	}
	for _, s := range []string{"", "exclude ", "block", "EXCLUDE"} {
		if _, err := ParseDecisionRuleType(s); err == nil {
			t.Errorf("ParseDecisionRuleType(%q): want error", s)
		}
	}
}

// mustDecisionRule is a test helper building a valid rule or failing the
// test.
func mustDecisionRule(t *testing.T, typ DecisionRuleType, target DecisionTarget, action *DecisionAction) DecisionRule {
	t.Helper()
	r, err := NewDecisionRule("dr1", typ, target, action, "manual correction", "alice", 2, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("NewDecisionRule(%s): unexpected error: %v", typ, err)
	}
	return r
}

// TestDecisionRuleValidation covers the shape rules of a decision rule:
// exclude without action, override with a valid action, mandatory reason,
// non-empty target, version >= 1 and a sane validity window.
func TestDecisionRuleValidation(t *testing.T) {
	target := DecisionTarget{CVEID: "CVE-2024-0001", Product: "widget"}
	if _, err := NewDecisionRule("dr1", DecisionRuleTypeExclude, target, nil, "not affected: bundled copy", "alice", 2, time.Time{}, time.Time{}); err != nil {
		t.Errorf("exclude without action: unexpected error: %v", err)
	}
	if _, err := NewDecisionRule("dr1", DecisionRuleTypeOverride, target, &DecisionAction{Method: MatchMethodExactIdentifier}, "forced", "alice", 2, time.Time{}, time.Time{}); err != nil {
		t.Errorf("override with action: unexpected error: %v", err)
	}
	if _, err := NewDecisionRule("dr1", DecisionRuleTypeOverride, target, &DecisionAction{Method: MatchMethodCandidate, Similarity: 42}, "forced candidate", "alice", 2, time.Time{}, time.Time{}); err != nil {
		t.Errorf("override to candidate with in-band similarity: unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		typ    DecisionRuleType
		target DecisionTarget
		action *DecisionAction
		reason string
	}{
		{"exclude with action", DecisionRuleTypeExclude, target, &DecisionAction{Method: MatchMethodExactIdentifier}, "r"},
		{"override without action", DecisionRuleTypeOverride, target, nil, "r"},
		{"override to no_match", DecisionRuleTypeOverride, target, &DecisionAction{Method: MatchMethodNoMatch}, "r"},
		{"override invalid method", DecisionRuleTypeOverride, target, &DecisionAction{Method: MatchMethod("purl")}, "r"},
		{"override candidate out of band", DecisionRuleTypeOverride, target, &DecisionAction{Method: MatchMethodCandidate, Similarity: 55}, "r"},
		{"override candidate out of band low", DecisionRuleTypeOverride, target, &DecisionAction{Method: MatchMethodCandidate, Similarity: 0}, "r"},
		{"override similarity on non-candidate", DecisionRuleTypeOverride, target, &DecisionAction{Method: MatchMethodExactIdentifier, Similarity: 30}, "r"},
		{"empty target", DecisionRuleTypeExclude, DecisionTarget{}, nil, "r"},
		{"empty reason", DecisionRuleTypeExclude, target, nil, ""},
	}
	for _, c := range cases {
		if _, err := NewDecisionRule("dr", c.typ, c.target, c.action, c.reason, "alice", 1, time.Time{}, time.Time{}); err == nil {
			t.Errorf("%s: want error, got nil", c.name)
		}
	}
	// Empty ids and bad versions.
	if _, err := NewDecisionRule("", DecisionRuleTypeExclude, target, nil, "r", "alice", 1, time.Time{}, time.Time{}); err == nil {
		t.Error("empty id: want error")
	}
	if _, err := NewDecisionRule("dr", DecisionRuleTypeExclude, target, nil, "r", "alice", 0, time.Time{}, time.Time{}); err == nil {
		t.Error("version 0: want error")
	}
	// Valid_until before valid_from.
	from := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := NewDecisionRule("dr", DecisionRuleTypeExclude, target, nil, "r", "alice", 1, from, until); err == nil {
		t.Error("valid_until before valid_from: want error")
	}
}

// TestDecisionRuleAppliesAt covers the validity window semantics:
// ValidFrom <= t < ValidUntil (half-open), open-ended bounds and explicit
// revocation.
func TestDecisionRuleAppliesAt(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	r, err := NewDecisionRule("dr1", DecisionRuleTypeExclude,
		DecisionTarget{Vendor: "acme"}, nil, "r", "alice", 1, from, until)
	if err != nil {
		t.Fatalf("NewDecisionRule: unexpected error: %v", err)
	}

	if !r.AppliesAt(from) {
		t.Error("rule must apply exactly at valid_from")
	}
	if !r.AppliesAt(from.Add(time.Hour)) {
		t.Error("rule must apply inside the window")
	}
	if r.AppliesAt(until) {
		t.Error("rule must not apply at valid_until (half-open window)")
	}
	if r.AppliesAt(from.Add(-time.Second)) {
		t.Error("rule must not apply before valid_from")
	}

	revoked, err := r.Revoke()
	if err != nil {
		t.Fatalf("Revoke: unexpected error: %v", err)
	}
	if revoked.AppliesAt(from.Add(time.Hour)) {
		t.Error("revoked rule must not apply")
	}
	if _, err := revoked.Revoke(); err == nil {
		t.Error("double Revoke: want error")
	}
	if r.Revoked {
		t.Error("Revoke must not mutate the receiver")
	}

	open, err := NewDecisionRule("dr2", DecisionRuleTypeOverride,
		DecisionTarget{Vendor: "acme"}, &DecisionAction{Method: MatchMethodExactIdentifier}, "r", "alice", 1, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("NewDecisionRule(open): unexpected error: %v", err)
	}
	if !open.AppliesAt(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) || !open.AppliesAt(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("a rule without a window must always apply while not revoked")
	}
}

// TestRulesetVersion covers the composite rule-version derivation
// "a<alias.version>d<decision.version>" (ARCH-003 §1.4/§3).
func TestRulesetVersion(t *testing.T) {
	got, err := RulesetVersion(3, 7)
	if err != nil || got != "a3d7" {
		t.Errorf("RulesetVersion(3, 7) = %q, %v; want a3d7", got, err)
	}
	if got, err := RulesetVersion(0, 0); err != nil || got != "a0d0" {
		t.Errorf("RulesetVersion(0, 0) = %q, %v; want a0d0 (no rules yet)", got, err)
	}
	if got, err := RulesetVersion(1, 0); err != nil || got != "a1d0" {
		t.Errorf("RulesetVersion(1, 0) = %q, %v; want a1d0", got, err)
	}
	if _, err := RulesetVersion(-1, 2); err == nil {
		t.Error("negative alias version: want error")
	}
	if _, err := RulesetVersion(1, -2); err == nil {
		t.Error("negative decision version: want error")
	}
}

// TestNewMatchDecisionFields covers the Match extension defaults: a raw
// computed match carries an empty reason list (jsonb '[]'), no decision
// rule and no auto_* triple.
func TestNewMatchDecisionFields(t *testing.T) {
	m, err := NewMatch("m1", "v1", "c1", MatchMethodCanonicalProductRange, 0)
	if err != nil {
		t.Fatalf("NewMatch: unexpected error: %v", err)
	}
	if m.Reasons == nil || len(m.Reasons) != 0 {
		t.Errorf("NewMatch Reasons = %#v, want a non-nil empty list", m.Reasons)
	}
	if m.DecisionRuleID != nil {
		t.Errorf("NewMatch DecisionRuleID = %v, want nil", *m.DecisionRuleID)
	}
	if m.AutoMethod != nil || m.AutoConfidence != nil || m.AutoScore != nil {
		t.Errorf("NewMatch auto_* = %v/%v/%v, want all nil", m.AutoMethod, m.AutoConfidence, m.AutoScore)
	}
	if m.RuleVersion != MatchRuleVersion {
		t.Errorf("NewMatch RuleVersion = %q, want %q", m.RuleVersion, MatchRuleVersion)
	}
}

// TestApplyDecisionRuleExclude covers the exclude outcome (ADR-015): the
// effective match is a no_match that references the rule, keeps its
// reasons, stamps the ruleset version and sets no auto_* triple.
func TestApplyDecisionRuleExclude(t *testing.T) {
	raw, err := NewMatch("m1", "v1", "c1", MatchMethodCanonicalProductRange, 0)
	if err != nil {
		t.Fatalf("NewMatch: unexpected error: %v", err)
	}
	raw.Reasons = append(raw.Reasons, "cpe match on vendor/product")

	rule := mustDecisionRule(t, DecisionRuleTypeExclude, DecisionTarget{Vendor: "acme"}, nil)
	ruleVersion, err := RulesetVersion(2, rule.Version)
	if err != nil {
		t.Fatalf("RulesetVersion: unexpected error: %v", err)
	}
	out, err := raw.ApplyDecisionRule(rule.ID, rule, ruleVersion)
	if err != nil {
		t.Fatalf("ApplyDecisionRule(exclude): unexpected error: %v", err)
	}
	if out.Method != MatchMethodNoMatch || out.Confidence != ConfidenceNone || out.Score != 0 {
		t.Errorf("exclude outcome = %s/%s/%d, want no_match/none/0", out.Method, out.Confidence, out.Score)
	}
	if out.DecisionRuleID == nil || *out.DecisionRuleID != rule.ID {
		t.Errorf("exclude outcome DecisionRuleID = %v, want %q (the exclusion is visible and auditable)", out.DecisionRuleID, rule.ID)
	}
	if out.AutoMethod != nil || out.AutoConfidence != nil || out.AutoScore != nil {
		t.Errorf("exclude outcome must not set auto_* (only an override preserves the computed triple): %v/%v/%v", out.AutoMethod, out.AutoConfidence, out.AutoScore)
	}
	if out.RuleVersion != ruleVersion {
		t.Errorf("exclude outcome RuleVersion = %q, want %q", out.RuleVersion, ruleVersion)
	}
	if len(out.Reasons) != 1 || out.Reasons[0] != "cpe match on vendor/product" {
		t.Errorf("exclude outcome Reasons = %v, want the raw reasons preserved", out.Reasons)
	}
	if out.ID != raw.ID || out.VulnerabilityID != raw.VulnerabilityID || out.ComponentID != raw.ComponentID {
		t.Error("exclude outcome must keep the match identity")
	}
}

// TestApplyDecisionRuleOverride covers the override outcome (ADR-015):
// the effective method/confidence/score are the forced values while the
// raw computed triple moves into auto_* and stays reversible.
func TestApplyDecisionRuleOverride(t *testing.T) {
	raw, err := NewMatch("m1", "v1", "c1", MatchMethodExactIdentifier, 0)
	if err != nil {
		t.Fatalf("NewMatch: unexpected error: %v", err)
	}

	rule := mustDecisionRule(t, DecisionRuleTypeOverride,
		DecisionTarget{CVEID: "CVE-2024-0001"},
		&DecisionAction{Method: MatchMethodProductUncertainVersion})
	ruleVersion, err := RulesetVersion(2, rule.Version)
	if err != nil {
		t.Fatalf("RulesetVersion: unexpected error: %v", err)
	}
	out, err := raw.ApplyDecisionRule(rule.ID, rule, ruleVersion)
	if err != nil {
		t.Fatalf("ApplyDecisionRule(override): unexpected error: %v", err)
	}
	if out.Method != MatchMethodProductUncertainVersion || out.Confidence != ConfidenceMedium || out.Score != 65 {
		t.Errorf("override outcome = %s/%s/%d, want product_uncertain_version/medium/65", out.Method, out.Confidence, out.Score)
	}
	if out.DecisionRuleID == nil || *out.DecisionRuleID != rule.ID {
		t.Errorf("override outcome DecisionRuleID = %v, want the rule id", out.DecisionRuleID)
	}
	if out.AutoMethod == nil || *out.AutoMethod != MatchMethodExactIdentifier ||
		out.AutoConfidence == nil || *out.AutoConfidence != ConfidenceHigh ||
		out.AutoScore == nil || *out.AutoScore != 100 {
		t.Errorf("override outcome auto_* = %v/%v/%v, want the raw exact_identifier/high/100 triple",
			out.AutoMethod, out.AutoConfidence, out.AutoScore)
	}
	if out.RuleVersion != ruleVersion {
		t.Errorf("override outcome RuleVersion = %q, want %q", out.RuleVersion, ruleVersion)
	}

	// Override to candidate carries the manually forced similarity.
	candRule := mustDecisionRule(t, DecisionRuleTypeOverride,
		DecisionTarget{ComponentID: "c1"},
		&DecisionAction{Method: MatchMethodCandidate, Similarity: 42})
	out, err = raw.ApplyDecisionRule(candRule.ID, candRule, ruleVersion)
	if err != nil {
		t.Fatalf("ApplyDecisionRule(override candidate): unexpected error: %v", err)
	}
	if out.Method != MatchMethodCandidate || out.Confidence != ConfidenceLow || out.Score != 42 {
		t.Errorf("candidate override outcome = %s/%s/%d, want candidate/low/42", out.Method, out.Confidence, out.Score)
	}
	if out.AutoScore == nil || *out.AutoScore != 100 {
		t.Errorf("candidate override auto_score = %v, want the raw 100", out.AutoScore)
	}
}

// TestApplyDecisionRuleValidation covers the guard rails of the outcome
// stamping: revoked rules, missing identities and empty rule versions
// error; the raw match is never mutated.
func TestApplyDecisionRuleValidation(t *testing.T) {
	raw, err := NewMatch("m1", "v1", "c1", MatchMethodExactIdentifier, 0)
	if err != nil {
		t.Fatalf("NewMatch: unexpected error: %v", err)
	}
	rule := mustDecisionRule(t, DecisionRuleTypeOverride,
		DecisionTarget{Vendor: "acme"},
		&DecisionAction{Method: MatchMethodExactIdentifier})
	ruleVersion, _ := RulesetVersion(1, 1)

	revoked, err := rule.Revoke()
	if err != nil {
		t.Fatalf("Revoke: unexpected error: %v", err)
	}
	if _, err := raw.ApplyDecisionRule(rule.ID, revoked, ruleVersion); err == nil {
		t.Error("revoked rule: want error")
	}
	if _, err := raw.ApplyDecisionRule("", rule, ruleVersion); err == nil {
		t.Error("empty rule id: want error")
	}
	if _, err := raw.ApplyDecisionRule(rule.ID, rule, ""); err == nil {
		t.Error("empty rule version: want error")
	}
	if _, err := raw.ApplyDecisionRule(rule.ID, rule, ruleVersion); err != nil {
		t.Errorf("valid override: unexpected error: %v", err)
	}
	if raw.AutoMethod != nil || raw.DecisionRuleID != nil {
		t.Error("ApplyDecisionRule must return a new match, not mutate the receiver")
	}
}
