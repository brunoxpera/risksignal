package domain

import (
	"encoding/json"
	"testing"
)

func predFactors(conf Confidence, kev bool, cvss, epss float64, crit Criticality, exp Exposure) PriorityFactors {
	return PriorityFactors{Confidence: conf, KEV: kev, CVSS: cvss, EPSS: epss, Criticality: crit, Exposure: exp}
}

// TestEvaluateRuleSemantics covers the group/atomic forms and the
// all_of/any_of semantics.
func TestEvaluateRuleSemantics(t *testing.T) {
	f := predFactors(ConfidenceHigh, true, 9.8, 0.99, CriticalityCritical, ExposureInternet)

	eqBool := RuleDefinition{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)}
	eqStr := RuleDefinition{Op: RuleOpEq, Field: FieldExposure, Value: StringValue("internet")}
	inSet := RuleDefinition{Op: RuleOpIn, Field: FieldConfidence, Values: []string{"high", "medium"}}
	geCVSS := RuleDefinition{Op: RuleOpGe, Field: FieldCVSS, Value: NumberValue(9.0)}
	geEPSS := RuleDefinition{Op: RuleOpGe, Field: FieldEPSS, Value: NumberValue(0.95)}

	tests := []struct {
		name string
		def  RuleDefinition
		want bool
	}{
		{"eq bool true", eqBool, true},
		{"eq bool false", RuleDefinition{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(false)}, false},
		{"eq string hit", eqStr, true},
		{"eq string miss", RuleDefinition{Op: RuleOpEq, Field: FieldExposure, Value: StringValue("internal")}, false},
		{"in hit", inSet, true},
		{"in miss", RuleDefinition{Op: RuleOpIn, Field: FieldCriticality, Values: []string{"normal", "low"}}, false},
		{"ge cvss at threshold", geCVSS, true},
		{"ge cvss above", RuleDefinition{Op: RuleOpGe, Field: FieldCVSS, Value: NumberValue(9.9)}, false},
		{"ge epss", geEPSS, true},
		{"all_of all true", RuleDefinition{AllOf: []RuleDefinition{eqBool, eqStr, geCVSS}}, true},
		{"all_of one false", RuleDefinition{AllOf: []RuleDefinition{eqBool, {Op: RuleOpIn, Field: FieldConfidence, Values: []string{"low"}}}}, false},
		{"any_of one true", RuleDefinition{AnyOf: []RuleDefinition{{Op: RuleOpIn, Field: FieldConfidence, Values: []string{"low"}}, eqStr}}, true},
		{"any_of none true", RuleDefinition{AnyOf: []RuleDefinition{{Op: RuleOpIn, Field: FieldConfidence, Values: []string{"low"}}, {Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(false)}}}, false},
		{"nested any_of inside all_of", RuleDefinition{AllOf: []RuleDefinition{eqBool, {AnyOf: []RuleDefinition{eqStr, {Op: RuleOpIn, Field: FieldConfidence, Values: []string{"low"}}}}}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluateRule(tc.def, f)
			if err != nil {
				t.Fatalf("EvaluateRule: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("EvaluateRule = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEvaluateRuleErrors pins the closed vocabulary: unknown ops, fields and
// values — and malformed nodes — are errors, never silent non-matches.
func TestEvaluateRuleErrors(t *testing.T) {
	f := predFactors(ConfidenceHigh, true, 9.8, 0.99, CriticalityCritical, ExposureInternet)
	bad := []struct {
		name string
		def  RuleDefinition
	}{
		{"empty node", RuleDefinition{}},
		{"mixed group and atomic", RuleDefinition{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true), AllOf: []RuleDefinition{{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)}}}},
		{"unknown op", RuleDefinition{Op: RuleOp("~="), Field: FieldConfidence, Values: []string{"high"}}},
		{"unknown field", RuleDefinition{Op: RuleOpEq, Field: FactorField("score"), Value: StringValue("high")}},
		{"in with unknown value", RuleDefinition{Op: RuleOpIn, Field: FieldConfidence, Values: []string{"sometimes"}}},
		{"eq with unknown string value", RuleDefinition{Op: RuleOpEq, Field: FieldExposure, Value: StringValue("public")}},
		{"eq on numeric field", RuleDefinition{Op: RuleOpEq, Field: FieldCVSS, Value: NumberValue(9.0)}},
		{"ge on non-numeric field", RuleDefinition{Op: RuleOpGe, Field: FieldConfidence, Value: NumberValue(1)}},
		{"ge with string value", RuleDefinition{Op: RuleOpGe, Field: FieldCVSS, Value: StringValue("9")}},
		{"eq with wrong value kind", RuleDefinition{Op: RuleOpEq, Field: FieldKEV, Value: StringValue("true")}},
		{"in with empty values", RuleDefinition{Op: RuleOpIn, Field: FieldConfidence, Values: nil}},
		{"eq carrying values", RuleDefinition{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true), Values: []string{"x"}}},
		{"ge carrying values", RuleDefinition{Op: RuleOpGe, Field: FieldCVSS, Value: NumberValue(9), Values: []string{"x"}}},
		{"nested bad node", RuleDefinition{AllOf: []RuleDefinition{{Op: RuleOpIn, Field: FieldKEV, Values: []string{"true"}}}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EvaluateRule(tc.def, f); err == nil {
				t.Errorf("EvaluateRule(%s): want error, got nil", tc.name)
			}
		})
	}
}

// TestRuleDefinitionJSONRoundTrip pins the typed JSON-tagged shape
// ({"op":"eq","field":"kev","value":true}) and that it round-trips: the
// domain carries the struct, never a raw jsonb/pgx value.
func TestRuleDefinitionJSONRoundTrip(t *testing.T) {
	def := RuleDefinition{AllOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldConfidence, Values: []string{"high"}},
		{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)},
		{AnyOf: []RuleDefinition{
			{Op: RuleOpIn, Field: FieldCriticality, Values: []string{"critical", "high"}},
			{Op: RuleOpEq, Field: FieldExposure, Value: StringValue("internet")},
		}},
		{Op: RuleOpGe, Field: FieldCVSS, Value: NumberValue(9.0)},
	}}
	raw, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back RuleDefinition
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	f := predFactors(ConfidenceHigh, true, 9.8, 0.99, CriticalityCritical, ExposureInternet)
	got, err := EvaluateRule(back, f)
	if err != nil {
		t.Fatalf("EvaluateRule after round-trip: %v", err)
	}
	if !got {
		t.Error("round-tripped definition must still match")
	}
}
