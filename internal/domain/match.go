package domain

import "fmt"

// Match links a vulnerability to an inventory component (ch. 6.1, ARCH-001
// §1 matches; ARCH-003 §3 extends the aggregate). Matching is method-led
// (ADR-015): the method is authoritative and confidence plus the derived
// sort-rank score follow from it through the versioned mapping
// (mapping.go, tagged MatchRuleVersion) — they are never stored or set
// independently. Use NewMatch to construct a Match with that invariant;
// the field block mirrors the table columns (minus created_at) so the
// persistence layer can scan rows back into plain structs.
//
// Score is the sort rank of ch. 9.2 (100/95/90/80/65/55, 0 for no_match);
// only for candidate it carries the actually computed similarity. The
// uniqueness key (vulnerability_id, component_id, rule_version) makes a
// re-run idempotent at the application layer.
//
// I3 adds the decision-rule fields (ARCH-003 §3, ADR-015): Reasons is the
// auditable rationale list of TR-007 (jsonb, NOT NULL '[]');
// DecisionRuleID references the decision rule that produced this match
// (an exclusion or an override); and for overrides the raw computed
// starting point stays visible in AutoMethod/AutoConfidence/AutoScore —
// set only when a rule overrode, so the override stays reversible. Use
// ApplyDecisionRule to stamp a decision-rule outcome onto a raw computed
// match; nothing else may set those fields.
type Match struct {
	ID              string // uuid
	VulnerabilityID string
	ComponentID     string
	Method          MatchMethod
	Confidence      Confidence
	Score           int
	RuleVersion     string

	Reasons        []string // TR-007 rationale list; jsonb, never nil after construction
	DecisionRuleID *string  // decision rule that produced this match; nil = purely computed

	// AutoMethod/AutoConfidence/AutoScore preserve the raw computed triple
	// when a decision rule overrode it (ADR-015); nil when no rule
	// overrode. They mirror auto_method/auto_confidence/auto_score.
	AutoMethod     *MatchMethod
	AutoConfidence *Confidence
	AutoScore      *int
}

// NewMatch validates and assembles a Match, deriving confidence and the
// sort-rank score from the authoritative method through the ADR-015
// mapping (candidateSimilarity is the actually computed similarity,
// required for candidate only) and stamping the mapping rule version. The
// match starts purely computed: an empty reason list (jsonb '[]'), no
// decision rule and no auto_* triple. Constructing a Match any other way
// risks a method/confidence/score triple the mapping would never produce.
func NewMatch(id, vulnerabilityID, componentID string, method MatchMethod, candidateSimilarity int) (Match, error) {
	if id == "" {
		return Match{}, fmt.Errorf("domain: match id must not be empty")
	}
	if vulnerabilityID == "" {
		return Match{}, fmt.Errorf("domain: match vulnerability_id must not be empty")
	}
	if componentID == "" {
		return Match{}, fmt.Errorf("domain: match component_id must not be empty")
	}
	conf, score, err := method.Derive(candidateSimilarity)
	if err != nil {
		return Match{}, err
	}
	return Match{
		ID:              id,
		VulnerabilityID: vulnerabilityID,
		ComponentID:     componentID,
		Method:          method,
		Confidence:      conf,
		Score:           score,
		RuleVersion:     MatchRuleVersion,
		Reasons:         []string{},
	}, nil
}

// ApplyDecisionRule stamps the outcome of a decision rule onto a raw
// computed match (ADR-015, ARCH-003 §3 — decision rules must survive
// matching.rebuild). The rule must be applicable (not revoked; the
// validity window is the caller's clock concern via DecisionRule.AppliesAt)
// and its shape is enforced:
//
//   - exclude: the effective match is a no_match (method no_match,
//     confidence none, score 0) referencing the rule — the exclusion is
//     visible and auditable and keeps UQ (vulnerability_id, component_id,
//     rule_version) valid. No auto_* fields are set: only an override
//     preserves the computed starting point.
//   - override: the effective method/confidence/score are the forced
//     action values (derived through the ADR-015 mapping, candidate
//     similarity included), the raw triple moves into auto_* and the rule
//     is referenced.
//
// The caller supplies ruleVersion — the composite "a<n>d<m>" of the
// current ruleset (RulesetVersion) — so the row's rule_version matches the
// ruleset it was computed under. Reasons are preserved: the caller appends
// its computed rationale before persisting.
func (m Match) ApplyDecisionRule(ruleID string, rule DecisionRule, ruleVersion string) (Match, error) {
	if ruleID == "" {
		return Match{}, fmt.Errorf("domain: match decision rule: rule id must not be empty")
	}
	if rule.Revoked {
		return Match{}, fmt.Errorf("domain: match decision rule %s is revoked", ruleID)
	}
	if ruleVersion == "" {
		return Match{}, fmt.Errorf("domain: match decision rule: rule_version must not be empty")
	}
	reasons := make([]string, len(m.Reasons))
	copy(reasons, m.Reasons)
	out := m
	out.Reasons = reasons
	out.RuleVersion = ruleVersion
	out.DecisionRuleID = &ruleID

	switch rule.Type {
	case DecisionRuleTypeExclude:
		// An exclusion emits a visible no_match that references the rule.
		conf, score, err := MatchMethodNoMatch.Derive(0)
		if err != nil {
			return Match{}, fmt.Errorf("domain: match decision rule exclude: %w", err)
		}
		out.Method = MatchMethodNoMatch
		out.Confidence = conf
		out.Score = score
		return out, nil
	case DecisionRuleTypeOverride:
		if rule.Action == nil {
			return Match{}, fmt.Errorf("domain: match decision rule override %s: rule carries no action", ruleID)
		}
		conf, score, err := rule.Action.Method.Derive(rule.Action.Similarity)
		if err != nil {
			return Match{}, fmt.Errorf("domain: match decision rule override %s: %w", ruleID, err)
		}
		// Preserve the raw computed triple; set the effective values.
		autoMethod, autoConf, autoScore := m.Method, m.Confidence, m.Score
		out.Method = rule.Action.Method
		out.Confidence = conf
		out.Score = score
		out.AutoMethod = &autoMethod
		out.AutoConfidence = &autoConf
		out.AutoScore = &autoScore
		return out, nil
	default:
		return Match{}, fmt.Errorf("domain: match decision rule: invalid DecisionRuleType %q", rule.Type)
	}
}
