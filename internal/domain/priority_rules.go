package domain

import "fmt"

// This file owns the I4 priority_rules model of ARCH-004 §1: the versioned,
// copy-on-write ruleset snapshot that replaces the hard-coded I1b
// ComputePriority switch (ADR-015, ARCH-003 §1.4). Each signal references
// exactly one snapshot via rule_version, so "den verwendeten Regelstand"
// (ch. 9.3) is a single immutable value.
//
// The seeded ruleset version 1 (SeedPriorityRules) reproduces the ch. 9.3
// rules verbatim — P1→P4, first match wins, P4 terminal — so replacing the
// I1b stub is behaviour-preserving (the reference matrix test pins this).

// PriorityRuleVersionI1b is the legacy I1b priority-rule tag. It stays
// valid as *history*: rows written by I1b keep it (rule_version records the
// version the priority was computed under, immutable), while the I4
// ruleset uses the zero-padded "p<n>" form of PriorityRuleVersion. The I1b
// create path stamps this until the effective version is read through the
// PriorityRuleRepo port (WP-4.04).
const PriorityRuleVersionI1b = "i1b-1"

// SeedPriorityRulesVersion is the ruleset snapshot version the I4 migration
// seeds (ARCH-004 §7): the ch. 9.3 ruleset, inserted as four rows
// (rule_id P1..P4, version 1).
const SeedPriorityRulesVersion = 1

// priorityRuleVersionWidth is the fixed digit width of the version string.
// Zero-padding makes text ordering follow numeric ordering — the same
// lexical-ordering contract as RulesetVersion (DEV-057); the effective
// version is MAX(version) and rule_version is a text column ordered by it.
const priorityRuleVersionWidth = 10

// PriorityRuleVersion returns the stable string form of the ruleset snapshot
// version n: "p%010d" (ARCH-004 §1). Snapshot versions start at 1; a
// non-positive n is a caller error. The zero-padded form is what a signal's
// rule_version stores and what the priority.recompute dedupe key carries.
func PriorityRuleVersion(n int) (string, error) {
	if n < 1 {
		return "", fmt.Errorf("domain: priority rule version %d must be >= 1", n)
	}
	return fmt.Sprintf("p%0*d", priorityRuleVersionWidth, n), nil
}

// PriorityRule is one row of a priority_rules snapshot (ARCH-004 §1): the
// stable rule id (the class the rule produces, P1..P4), the snapshot
// Version, the bounded Definition predicate (predicate.go), the Enabled
// flag (a disabled rule is inert — a disabled P1 demotes to the next
// matching rule) and the publish Reason/ActorID. Timestamps and the row id
// belong to the application layer behind the clock port.
type PriorityRule struct {
	RuleID     Priority
	Version    int
	Definition RuleDefinition
	Enabled    bool
	Reason     string
	ActorID    string
}

// Validate checks the value-level invariants of a rule: a known priority
// class, a positive snapshot version, a non-empty publishing actor and a
// structurally valid predicate definition.
func (r PriorityRule) Validate() error {
	if !r.RuleID.Valid() {
		return fmt.Errorf("domain: invalid PriorityRule rule_id %q", r.RuleID)
	}
	if r.Version < 1 {
		return fmt.Errorf("domain: priority rule version %d must be >= 1", r.Version)
	}
	if r.ActorID == "" {
		return fmt.Errorf("domain: priority rule %s actor_id must not be empty", r.RuleID)
	}
	if err := validateRuleNode(r.Definition); err != nil {
		return err
	}
	return nil
}

// NewPriorityRule validates and assembles an enabled priority rule.
func NewPriorityRule(ruleID Priority, version int, def RuleDefinition, reason, actorID string) (PriorityRule, error) {
	r := PriorityRule{
		RuleID:     ruleID,
		Version:    version,
		Definition: def,
		Enabled:    true,
		Reason:     reason,
		ActorID:    actorID,
	}
	if err := r.Validate(); err != nil {
		return PriorityRule{}, err
	}
	return r, nil
}

// Disable returns a copy with Enabled false; Enable returns a copy with
// Enabled true. Both are explicit value transitions — a rule is never
// silently toggled.
func (r PriorityRule) Disable() PriorityRule {
	r.Enabled = false
	return r
}

// Enable returns a copy with Enabled true.
func (r PriorityRule) Enable() PriorityRule {
	r.Enabled = true
	return r
}

// SeedPriorityRules returns the ch. 9.3 ruleset version 1 (ARCH-004 §1.1):
// the four rules P1→P4 evaluated first-match-wins with P4 terminal. The
// definitions are the typed predicate trees of the migration seed; the set
// is the ruleset the reference-matrix test proves reproduces the I1b
// ComputePriority outputs for every factor cell.
func SeedPriorityRules() []PriorityRule {
	const actor = "system"
	const reason = "ch. 9.3 deterministic priority rules (I4 ruleset v1)"
	return []PriorityRule{
		{RuleID: PriorityP1, Version: SeedPriorityRulesVersion, Enabled: true, ActorID: actor, Reason: reason, Definition: seedP1()},
		{RuleID: PriorityP2, Version: SeedPriorityRulesVersion, Enabled: true, ActorID: actor, Reason: reason, Definition: seedP2()},
		{RuleID: PriorityP3, Version: SeedPriorityRulesVersion, Enabled: true, ActorID: actor, Reason: reason, Definition: seedP3()},
		{RuleID: PriorityP4, Version: SeedPriorityRulesVersion, Enabled: true, ActorID: actor, Reason: reason, Definition: seedP4()},
	}
}

// seedP1 is the ch. 9.3 P1 predicate: confidence high AND kev AND
// (criticality critical/high OR exposure internet).
func seedP1() RuleDefinition {
	return RuleDefinition{AllOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceHigh)}},
		{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)},
		seedExposedOrCritical(),
	}}
}

// seedP2 is the ch. 9.3 P2 predicate:
//
//	(high AND (kev OR cvss >= 9.0 OR epss >= 0.95))
//	OR (medium AND kev AND (criticality critical/high OR exposure internet)).
func seedP2() RuleDefinition {
	return RuleDefinition{AnyOf: []RuleDefinition{
		{AllOf: []RuleDefinition{
			{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceHigh)}},
			{AnyOf: []RuleDefinition{
				{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)},
				{Op: RuleOpGe, Field: FieldCVSS, Value: NumberValue(cvssP2Threshold)},
				{Op: RuleOpGe, Field: FieldEPSS, Value: NumberValue(epssP2Threshold)},
			}},
		}},
		{AllOf: []RuleDefinition{
			{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceMedium)}},
			{Op: RuleOpEq, Field: FieldKEV, Value: BoolValue(true)},
			seedExposedOrCritical(),
		}},
	}}
}

// seedP3 is the ch. 9.3 P3 predicate: a plausible assignment, i.e. high or
// medium confidence reaching this rule — every P1/P2 urgency case was
// already consumed by the earlier, higher-precedence rules. The bounded
// language has no negation, so the "high AND NOT a strong urgency indicator"
// half of the prose is expressed by first-match-wins order, not by a NOT
// operator (ARCH-004 §1.1 non-goal).
func seedP3() RuleDefinition {
	return RuleDefinition{AllOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceHigh), string(ConfidenceMedium)}},
	}}
}

// seedP4 is the ch. 9.3 P4 fallback: no confirmed inventory assignment
// (low candidate or none). P4 is terminal — the evaluator returns it when no
// earlier rule matched (see EvaluatePriority).
func seedP4() RuleDefinition {
	return RuleDefinition{AllOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldConfidence, Values: []string{string(ConfidenceLow), string(ConfidenceNone)}},
	}}
}

// seedExposedOrCritical is the shared asset-context disjunct of the P1 and
// P2-medium branches: criticality critical/high OR exposure internet.
func seedExposedOrCritical() RuleDefinition {
	return RuleDefinition{AnyOf: []RuleDefinition{
		{Op: RuleOpIn, Field: FieldCriticality, Values: []string{string(CriticalityCritical), string(CriticalityHigh)}},
		{Op: RuleOpEq, Field: FieldExposure, Value: StringValue(string(ExposureInternet))},
	}}
}

// EvaluatePriority evaluates an ordered ruleset against the factors and
// returns the class of the first enabled rule whose predicate matches (ch.
// 9.3, first match wins). P4 is terminal: when no enabled rule matches — the
// P4 row is disabled or absent — the result is P4, never an error and never a
// silent reclassification to a stricter class. A malformed definition is an
// error.
func EvaluatePriority(rules []PriorityRule, factors PriorityFactors) (Priority, error) {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		ok, err := EvaluateRule(r.Definition, factors)
		if err != nil {
			return "", fmt.Errorf("domain: priority rule %s: %w", r.RuleID, err)
		}
		if ok {
			return r.RuleID, nil
		}
	}
	return PriorityP4, nil
}

// Thresholds of the ch. 9.3 rules, kept as constants so the rule table and
// its seed read as documentation.
const (
	// cvssP2Threshold: a high-confidence match is urgent from CVSS >= 9.0.
	cvssP2Threshold = 9.0
	// epssP2Threshold: a high-confidence match is urgent from an EPSS
	// percentile >= 0.95.
	epssP2Threshold = 0.95
)

// Validate checks the cross-field invariants of the factors before they are
// stored with a signal: a known method whose ADR-015-derived confidence
// equals Confidence (method stays authoritative), a known criticality and
// exposure, and in-range CVSS/EPSS values. CVSS is a base score in [0,10];
// EPSS a probability/percentile in [0,1].
func (f PriorityFactors) Validate() error {
	if !f.Method.Valid() {
		return fmt.Errorf("domain: invalid match method %q in priority factors", f.Method)
	}
	derived, ok := f.Method.Confidence()
	if !ok || derived != f.Confidence {
		return fmt.Errorf("domain: confidence %q inconsistent with method %q (ADR-015 derives %q)", f.Confidence, f.Method, derived)
	}
	if !f.Criticality.Valid() {
		return fmt.Errorf("domain: invalid criticality %q in priority factors", f.Criticality)
	}
	if !f.Exposure.Valid() {
		return fmt.Errorf("domain: invalid exposure %q in priority factors", f.Exposure)
	}
	if f.CVSS < 0 || f.CVSS > 10 {
		return fmt.Errorf("domain: cvss %v outside [0,10] in priority factors", f.CVSS)
	}
	if f.EPSS < 0 || f.EPSS > 1 {
		return fmt.Errorf("domain: epss %v outside [0,1] in priority factors", f.EPSS)
	}
	return nil
}

// ComputePriority returns the priority of the ch. 9.3 seed ruleset for the
// factors. It is the compatibility entry point of the I1b path: it now runs
// the versioned seed ruleset (SeedPriorityRules) through the bounded
// evaluator instead of the removed hard-coded switch, so its result is
// identical for every factor cell and the I1b callers keep working until the
// I4 use cases (WP-4.04) read the effective version through the port. The
// seed is a compile-time-valid ruleset, so the evaluation cannot error.
func ComputePriority(f PriorityFactors) Priority {
	p, err := EvaluatePriority(SeedPriorityRules(), f)
	if err != nil {
		return PriorityP4
	}
	return p
}
