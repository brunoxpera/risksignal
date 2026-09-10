package domain

import (
	"strings"
	"testing"
)

// This file tests ValidateRuleset (DEV-086): the operator-supplied ruleset
// gate of the configurable priority-rules publication (ARCH-004 §1). The
// validators accept the seed and an operator-style variant and reject every
// malformed, reordered, duplicated and degenerate (always-matching /
// unreachable / class-collapsing) ruleset.

// customRuleset is an operator-style ruleset distinct from the seed that
// still distinguishes all four classes: P1 = high confidence AND KEV, P2 =
// high confidence AND cvss >= 8.0, P3 = high/medium confidence, P4 =
// low/none. On a high/no-KEV/cvss 8.5 cell it resolves to P2 where the seed
// resolves to P3 — the observable difference the publish/recompute tests pin.
func customRuleset() []PriorityRule {
	ids := []Priority{PriorityP1, PriorityP2, PriorityP3, PriorityP4}
	defs := []RuleDefinition{
		{AllOf: []RuleDefinition{
			{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceHigh)}},
			{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)},
		}},
		{AllOf: []RuleDefinition{
			{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceHigh)}},
			{Op: RuleOpGe, Field: FieldCVSS, Value: NumberValue(8.0)},
		}},
		{AllOf: []RuleDefinition{
			{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceHigh), string(ConfidenceMedium)}},
		}},
		{AllOf: []RuleDefinition{
			{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceLow), string(ConfidenceNone)}},
		}},
	}
	rules := make([]PriorityRule, 4)
	for i := range ids {
		rules[i] = PriorityRule{RuleID: ids[i], Version: 1, Enabled: true, Reason: "operator-tuned thresholds", ActorID: "admin-1", Definition: defs[i]}
	}
	return rules
}

// allConfidences is a predicate that matches every factor cell — the
// always-matching shape a degenerate ruleset is built around.
func allConfidences() RuleDefinition {
	return RuleDefinition{AllOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldConfidence, Values: []string{
			string(ConfidenceHigh), string(ConfidenceMedium), string(ConfidenceLow), string(ConfidenceNone),
		}},
	}}
}

// TestValidateRulesetAcceptsSeedAndCustom accepts the seeded ch. 9.3 ruleset
// (the default) and an operator-style variant.
func TestValidateRulesetAcceptsSeedAndCustom(t *testing.T) {
	if err := ValidateRuleset(SeedPriorityRules()); err != nil {
		t.Fatalf("ValidateRuleset(seed): unexpected error: %v", err)
	}
	if err := ValidateRuleset(customRuleset()); err != nil {
		t.Fatalf("ValidateRuleset(custom): unexpected error: %v", err)
	}
}

// TestValidateRulesetRejectsShape covers the structural rejections: an empty
// or wrong-length set and duplicated / reordered / unknown rule ids.
func TestValidateRulesetRejectsShape(t *testing.T) {
	dupIDs := customRuleset()
	dupIDs[1].RuleID = PriorityP1 // two P1, no P2

	reordered := customRuleset()
	reordered[0], reordered[1] = reordered[1], reordered[0] // P2, P1, P3, P4

	unknown := customRuleset()
	unknown[3].RuleID = Priority("P9")

	tooFew := customRuleset()[:3]

	tests := []struct {
		name  string
		rules []PriorityRule
	}{
		{"nil", nil},
		{"empty", []PriorityRule{}},
		{"three rules", tooFew},
		{"duplicate id", dupIDs},
		{"reordered", reordered},
		{"unknown id", unknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRuleset(tc.rules); err == nil {
				t.Fatalf("ValidateRuleset(%s): want error, got nil", tc.name)
			}
		})
	}
}

// TestValidateRulesetRejectsBadDefinition rejects a rule whose predicate does
// not round-trip through the closed-vocabulary validation.
func TestValidateRulesetRejectsBadDefinition(t *testing.T) {
	cases := map[string]RuleDefinition{
		"empty definition":   {},
		"unknown op":         {Op: RuleOp("~="), Field: FieldConfidence, Values: []string{"high"}},
		"unknown field":      {Op: RuleOpIn, Field: FactorField("severity"), Values: []string{"high"}},
		"unknown value":      {Op: RuleOpIn, Field: FieldConfidence, Values: []string{"maybe"}},
		"mixed node":         {AllOf: []RuleDefinition{{Op: RuleOpIn, Field: FieldConfidence, Values: []string{"high"}}}, Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)},
		"eq wrong payload":   {Op: RuleOpEq, Field: FieldKEV, Value: StringValue("yes")},
		"ge on string field": {Op: RuleOpGe, Field: FieldConfidence, Value: NumberValue(1)},
	}
	for name, def := range cases {
		t.Run(name, func(t *testing.T) {
			rules := customRuleset()
			rules[1].Definition = def
			err := ValidateRuleset(rules)
			if err == nil {
				t.Fatalf("ValidateRuleset(%s): want error, got nil", name)
			}
		})
	}
}

// TestValidateRulesetRejectsDegenerate rejects rulesets that do not actually
// distinguish the classes: an always-matching rule (shadows the ones below),
// a class the set never produces, a duplicate predicate and a rule that can
// never fire.
func TestValidateRulesetRejectsDegenerate(t *testing.T) {
	// P1 always matches → P2/P3/P4 are unreachable.
	alwaysP1 := customRuleset()
	alwaysP1[0].Definition = allConfidences()

	// P3 always matches → P4 is never the winner.
	collapseP3 := customRuleset()
	collapseP3[2].Definition = allConfidences()

	// P2 duplicates P3's predicate → P3 can never win.
	duplicatePredicate := customRuleset()
	duplicatePredicate[1].Definition = duplicatePredicate[2].Definition

	// P2 requires cvss >= 11, impossible on the [0,10] scale → unreachable.
	unreachable := customRuleset()
	unreachable[1].Definition = RuleDefinition{AllOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceHigh)}},
		{Op: RuleOpGe, Field: FieldCVSS, Value: NumberValue(11)},
	}}

	tests := []struct {
		name  string
		rules []PriorityRule
		want  string // the unreachable class the error must name
	}{
		{"always-matching P1", alwaysP1, "P2"},
		{"class-collapsing P3", collapseP3, "P4"},
		{"duplicate predicate", duplicatePredicate, "P3"},
		{"unreachable rule", unreachable, "P2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRuleset(tc.rules)
			if err == nil {
				t.Fatalf("ValidateRuleset(%s): want a degenerate-ruleset error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateRuleset(%s) error = %q, want it to name %s", tc.name, err, tc.want)
			}
		})
	}
}

// TestCustomRulesetClassifiesCustomCell documents the difference the
// publish/recompute tests rely on: the seed resolves a high/no-KEV/cvss 8.5
// cell to P3, the custom ruleset resolves it to P2.
func TestCustomRulesetClassifiesCustomCell(t *testing.T) {
	f := PriorityFactors{Confidence: ConfidenceHigh, KEV: false, CVSS: 8.5, EPSS: 0.5, Criticality: CriticalityNormal, Exposure: ExposureInternal}
	if got := ComputePriority(f); got != PriorityP3 {
		t.Fatalf("seed ComputePriority(%+v) = %s, want P3", f, got)
	}
	got, err := EvaluatePriority(customRuleset(), f)
	if err != nil {
		t.Fatalf("EvaluatePriority(custom): unexpected error: %v", err)
	}
	if got != PriorityP2 {
		t.Fatalf("custom EvaluatePriority(%+v) = %s, want P2", f, got)
	}
}
