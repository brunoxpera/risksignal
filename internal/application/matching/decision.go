package matching

import (
	"fmt"
	"sort"

	"github.com/xpera/risksignal/internal/application/normalise"
	"github.com/xpera/risksignal/internal/domain"
)

// This file implements the decision_rules application of ARCH-003 §3
// (ch. 9.2, ADR-015): manual match corrections and exclusions that must
// survive automatic recompute. Automatic recomputation computes the raw
// result first (evaluate.go) and applies the rules of the current
// ruleset on top, recording both:
//
//   - an exclude rule matching the (cve, component) pair ⇒ the effective
//     outcome is a no_match (method no_match, confidence none, score 0)
//     that references the rule — the exclusion is visible, auditable and
//     keeps UQ (vulnerability_id, component_id, rule_version) valid (the
//     stored no_match row occupies the pair's key, so a rebuild cannot
//     silently re-add the automatic match);
//   - an override rule ⇒ the effective method/confidence/score are the
//     forced action values, while the raw computed triple is preserved in
//     AutoMethod/AutoConfidence/AutoScore so the computed starting point
//     stays visible and the override stays reversible (ch. 9.3 "der
//     berechnete Ausgangswert bleibt sichtbar").
//
// The semantics mirror domain.Match.ApplyDecisionRule exactly (the domain
// value object requires a match id, which the pure engine does not carry
// — the persistence layer of WP-3.08 assigns ids); the mapping of the
// forced method onto confidence/score goes through the same
// domain.MatchMethod.Derive, so both paths can never diverge.

// applyDecisionRules stamps the outcome of the applicable decision rule
// onto a raw computed outcome (ARCH-003 §3, ADR-015). Rules are the
// effective rules of the current ruleset version the caller read through
// its repository port (revoked rules are inert); applicability is
// evaluated against the pair and the clock instant Input.Now (revocation
// and the half-open validity window, domain.DecisionRule.AppliesAt).
//
// When several rules apply, the first in the deterministic rule order —
// sorted by (Version, ID), the ruleset version first, then the rule id —
// wins; conflicting rules are a ruleset data error and this first-match
// resolution keeps the outcome deterministic and auditable.
func applyDecisionRules(raw Outcome, in Input) (Outcome, error) {
	rule, ok := applicableDecisionRule(in)
	if !ok {
		return raw, nil
	}
	reasons := make([]string, len(raw.Reasons))
	copy(reasons, raw.Reasons)
	out := raw
	out.Reasons = reasons

	switch rule.Type {
	case domain.DecisionRuleTypeExclude:
		// An exclusion emits a visible no_match that references the rule
		// and keeps the pair's uniqueness key occupied (ADR-015). Only an
		// override preserves the computed starting point, so no auto_*
		// triple is set here.
		conf, score, err := domain.MatchMethodNoMatch.Derive(0)
		if err != nil {
			return Outcome{}, fmt.Errorf("matching: decision rule exclude %s: %w", rule.ID, err)
		}
		out.Method = domain.MatchMethodNoMatch
		out.Confidence = conf
		out.Score = score
		out.DecisionRuleID = &rule.ID
		out.Reasons = append(out.Reasons, fmt.Sprintf("excluded by decision rule %s: %s", rule.ID, rule.Reason))
		return out, nil

	case domain.DecisionRuleTypeOverride:
		// The effective triple is the forced action, the raw computed
		// triple moves into auto_* (reversible, ch. 9.3).
		if rule.Action == nil {
			return Outcome{}, fmt.Errorf("matching: decision rule override %s carries no action", rule.ID)
		}
		conf, score, err := rule.Action.Method.Derive(rule.Action.Similarity)
		if err != nil {
			return Outcome{}, fmt.Errorf("matching: decision rule override %s: %w", rule.ID, err)
		}
		autoMethod, autoConf, autoScore := raw.Method, raw.Confidence, raw.Score
		out.Method = rule.Action.Method
		out.Confidence = conf
		out.Score = score
		out.DecisionRuleID = &rule.ID
		out.AutoMethod = &autoMethod
		out.AutoConfidence = &autoConf
		out.AutoScore = &autoScore
		out.Reasons = append(out.Reasons, fmt.Sprintf("overridden by decision rule %s: %s", rule.ID, rule.Reason))
		return out, nil

	default:
		return Outcome{}, fmt.Errorf("matching: decision rule %s has invalid type %q", rule.ID, rule.Type)
	}
}

// applicableDecisionRule returns the decision rule of the input that
// applies to the (cve, component) pair, in the deterministic rule order
// (Version ascending, then ID ascending — the first applicable rule
// wins), or ok=false when no rule applies.
func applicableDecisionRule(in Input) (domain.DecisionRule, bool) {
	rules := make([]domain.DecisionRule, len(in.DecisionRules))
	copy(rules, in.DecisionRules)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Version != rules[j].Version {
			return rules[i].Version < rules[j].Version
		}
		return rules[i].ID < rules[j].ID
	})
	for _, r := range rules {
		if decisionRuleApplies(r, in) {
			return r, true
		}
	}
	return domain.DecisionRule{}, false
}

// decisionRuleApplies reports whether one decision rule covers the
// (cve, component) pair of the input: the rule must be effective at the
// clock instant (not revoked, inside the half-open validity window —
// domain.DecisionRule.AppliesAt) and every set target field must match —
// target_scope {cve_id?, vendor?, product?, component_id?}, an empty
// field is a wildcard (ARCH-003 §1.4). The vendor/product fields address
// the inventory component's normalised comparison keys (the side a
// manual correction is about); they are compared after the same fold the
// keys are stored under.
func decisionRuleApplies(r domain.DecisionRule, in Input) bool {
	if !r.AppliesAt(in.Now) {
		return false
	}
	t := r.Target
	if t.CVEID != "" && t.CVEID != in.CVEID {
		return false
	}
	if t.ComponentID != "" && t.ComponentID != in.Component.ID {
		return false
	}
	if t.Vendor != "" && t.Vendor != normalise.NormaliseKey(in.Component.VendorNorm) {
		return false
	}
	if t.Product != "" && t.Product != normalise.NormaliseKey(in.Component.ProductNorm) {
		return false
	}
	return true
}
