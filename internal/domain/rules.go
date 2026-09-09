package domain

import (
	"fmt"
	"time"
)

// This file defines the versioned matching rule value objects of ARCH-003
// §1.4 (ch. 7.1, ADR-015): alias_rules (controlled vendor/product aliases)
// and decision_rules (manual match corrections and exclusions that must
// survive automatic recompute). Both are pure configuration values — the
// ruleset versioning, the application of decision rules to computed matches
// and the alias closure are the matching use case's job (WP-3.04/3.06);
// the domain here owns shape, validation and the value-level semantics
// (validity windows, revocation, the effective rule version).

// AliasScope is the target of an alias rule (ARCH-003 §1.4 alias_rules:
// vendor | product).
type AliasScope string

// Allowed AliasScope values.
const (
	AliasScopeVendor  AliasScope = "vendor"
	AliasScopeProduct AliasScope = "product"
)

// Valid reports whether s is an allowed AliasScope value.
func (s AliasScope) Valid() bool {
	return s == AliasScopeVendor || s == AliasScopeProduct
}

// ParseAliasScope parses s into an AliasScope. Unknown values error.
func ParseAliasScope(s string) (AliasScope, error) {
	v := AliasScope(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid AliasScope %q", s)
	}
	return v, nil
}

// AliasRule maps one controlled vendor/product alias to its canonical value
// (ARCH-003 §1.4 alias_rules, ch. 9.1). from_value/to_value are already
// normalised (NFKC + trim + lowercase) at the boundary; alias resolution
// happens at match time through the symmetric one-hop closure of
// WP-3.04/3.06 — the domain stores the rule as a value. Version is the
// monotonic ruleset version (UQ (scope, from_value, version)); the
// composite effective rule version is derived by RulesetVersion from the
// alias and decision rule versions.
type AliasRule struct {
	ID      string // uuid
	Scope   AliasScope
	From    string // the alias/variant, normalised
	To      string // the canonical value, normalised
	Version int
	Enabled bool   // disabled rules are inert
	Reason  string // human rationale; "" when none recorded
}

// NewAliasRule validates and assembles an AliasRule: identities and both
// values are required, the scope must be known, the version must be a
// positive monotonic counter and an alias must not map to itself (a
// self-loop is a data error, not a rule). A new rule is enabled.
func NewAliasRule(id string, scope AliasScope, from, to, reason string, version int) (AliasRule, error) {
	if id == "" {
		return AliasRule{}, fmt.Errorf("domain: alias rule id must not be empty")
	}
	if !scope.Valid() {
		return AliasRule{}, fmt.Errorf("domain: invalid AliasScope %q", scope)
	}
	if from == "" {
		return AliasRule{}, fmt.Errorf("domain: alias rule from_value must not be empty")
	}
	if to == "" {
		return AliasRule{}, fmt.Errorf("domain: alias rule to_value must not be empty")
	}
	if from == to {
		return AliasRule{}, fmt.Errorf("domain: alias rule must not map %q to itself", from)
	}
	if version < 1 {
		return AliasRule{}, fmt.Errorf("domain: alias rule version %d must be >= 1", version)
	}
	return AliasRule{
		ID:      id,
		Scope:   scope,
		From:    from,
		To:      to,
		Version: version,
		Enabled: true,
		Reason:  reason,
	}, nil
}

// Disable returns a copy with Enabled false; Enable returns a copy with
// Enabled true. Both are explicit value transitions — a rule is never
// silently toggled by an import.
func (r AliasRule) Disable() AliasRule {
	r.Enabled = false
	return r
}

// Enable returns a copy with Enabled true.
func (r AliasRule) Enable() AliasRule {
	r.Enabled = true
	return r
}

// DecisionRuleType classifies a decision rule (ARCH-003 §1.4
// decision_rules.type: exclude | override, ADR-015).
type DecisionRuleType string

// Allowed DecisionRuleType values.
const (
	// DecisionRuleTypeExclude forces a no_match outcome for the matching
	// (cve, component) pairs the rule's target scope covers.
	DecisionRuleTypeExclude DecisionRuleType = "exclude"
	// DecisionRuleTypeOverride forces the rule's action (method, and the
	// candidate similarity when the forced method is candidate) onto the
	// matching outcome, preserving the computed starting point in the
	// match's auto_* fields.
	DecisionRuleTypeOverride DecisionRuleType = "override"
)

// Valid reports whether t is an allowed DecisionRuleType value.
func (t DecisionRuleType) Valid() bool {
	return t == DecisionRuleTypeExclude || t == DecisionRuleTypeOverride
}

// ParseDecisionRuleType parses s into a DecisionRuleType. Unknown values
// error.
func ParseDecisionRuleType(s string) (DecisionRuleType, error) {
	v := DecisionRuleType(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid DecisionRuleType %q", s)
	}
	return v, nil
}

// DecisionTarget is a decision rule's applicability scope (ARCH-003 §1.4
// target_scope jsonb: {cve_id?, vendor?, product?, component_id?}). An
// empty field is a wildcard; at least one field must be set — a rule
// matching nothing (or everything) is a configuration error. The matching
// engine decides whether a rule covers a concrete (vulnerability,
// component) pair; the domain only owns the shape.
type DecisionTarget struct {
	CVEID       string `json:"cve_id,omitempty"`       // CVE-YYYY-NNNNN
	Vendor      string `json:"vendor,omitempty"`       // normalised vendor
	Product     string `json:"product,omitempty"`      // normalised product
	ComponentID string `json:"component_id,omitempty"` // uuid of one component
}

// hasAny reports whether at least one target field is set.
func (t DecisionTarget) hasAny() bool {
	return t.CVEID != "" || t.Vendor != "" || t.Product != "" || t.ComponentID != ""
}

// DecisionAction is the forced outcome of an override rule (ARCH-003 §1.4
// action jsonb: the forced method plus the candidate similarity when the
// forced method is candidate — the one case where the score is computed
// input rather than a derived rank). Overrides never force no_match:
// excluding a pair is the exclude type's job.
type DecisionAction struct {
	Method     MatchMethod
	Similarity int // computed candidate similarity, required only for candidate
}

// DecisionRule is a manual match correction or exclusion (ARCH-003 §1.4
// decision_rules, ch. 9.2, ADR-015) that must survive automatic recompute.
// An exclude rule forces no_match; an override rule forces its action
// while the match keeps the raw computed values in auto_* (reversible).
//
// Reason is mandatory (ch. 9.2 — an audited correction without rationale
// is not a correction); Version is the monotonic ruleset version; the
// validity window ValidFrom ≤ t < ValidUntil (zero time = open-ended) and
// the explicit Revoked flag gate applicability — AppliesAt is the pure
// value-level test, the injected clock instant is supplied by the caller.
type DecisionRule struct {
	ID     string // uuid
	Type   DecisionRuleType
	Target DecisionTarget
	Action *DecisionAction // required for override; nil for exclude

	Reason  string // mandatory rationale
	Version int    // monotonic ruleset version
	ActorID string // author (audited)

	ValidFrom  time.Time // zero = no lower bound
	ValidUntil time.Time // zero = open-ended until revoked
	Revoked    bool      // explicit revocation (revoked_at stamped by the application layer)
}

// NewDecisionRule validates and assembles a DecisionRule: identities and
// the mandatory reason, a known type, a target with at least one field, a
// version >= 1 and an action exactly for override rules (a valid method —
// never no_match, which is the exclude type's semantics — and a candidate
// similarity inside the 1–54 band exactly when the method is candidate).
func NewDecisionRule(id string, typ DecisionRuleType, target DecisionTarget, action *DecisionAction, reason, actorID string, version int, validFrom, validUntil time.Time) (DecisionRule, error) {
	if id == "" {
		return DecisionRule{}, fmt.Errorf("domain: decision rule id must not be empty")
	}
	if !typ.Valid() {
		return DecisionRule{}, fmt.Errorf("domain: invalid DecisionRuleType %q", typ)
	}
	if !target.hasAny() {
		return DecisionRule{}, fmt.Errorf("domain: decision rule target_scope must set at least one of cve_id, vendor, product, component_id")
	}
	if reason == "" {
		return DecisionRule{}, fmt.Errorf("domain: decision rule reason must not be empty")
	}
	if version < 1 {
		return DecisionRule{}, fmt.Errorf("domain: decision rule version %d must be >= 1", version)
	}
	if !validUntil.IsZero() && validUntil.Before(validFrom) {
		return DecisionRule{}, fmt.Errorf("domain: decision rule valid_until %s is before valid_from %s", validUntil, validFrom)
	}
	rule := DecisionRule{
		ID:         id,
		Type:       typ,
		Target:     target,
		Action:     action,
		Reason:     reason,
		Version:    version,
		ActorID:    actorID,
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
	}
	switch typ {
	case DecisionRuleTypeExclude:
		if action != nil {
			return DecisionRule{}, fmt.Errorf("domain: exclude rule must not carry an action")
		}
	case DecisionRuleTypeOverride:
		if action == nil {
			return DecisionRule{}, fmt.Errorf("domain: override rule requires an action")
		}
		if !action.Method.Valid() {
			return DecisionRule{}, fmt.Errorf("domain: override rule action method %q is not a valid MatchMethod", action.Method)
		}
		if action.Method == MatchMethodNoMatch {
			return DecisionRule{}, fmt.Errorf("domain: override rule must not force no_match — use an exclude rule")
		}
		if action.Method == MatchMethodCandidate {
			if action.Similarity < candidateScoreMin || action.Similarity > candidateScoreMax {
				return DecisionRule{}, fmt.Errorf("domain: override rule candidate similarity %d outside [%d,%d]", action.Similarity, candidateScoreMin, candidateScoreMax)
			}
		} else if action.Similarity != 0 {
			return DecisionRule{}, fmt.Errorf("domain: override rule similarity is only set for candidate, got method %q with similarity %d", action.Method, action.Similarity)
		}
	}
	return rule, nil
}

// Revoke explicitly revokes the rule (ch. 9.2: a decision rule stays valid
// "bis sie abgelaufen oder aufgehoben ist"). Revocation is a guarded value
// transition: an already-revoked rule cannot be revoked again; the
// revoked_at timestamp is applied by the application layer.
func (r DecisionRule) Revoke() (DecisionRule, error) {
	if r.Revoked {
		return DecisionRule{}, fmt.Errorf("domain: decision rule %s is already revoked", r.ID)
	}
	r.Revoked = true
	return r, nil
}

// AppliesAt reports whether the rule is effective at the instant t: it must
// not be revoked and t must lie inside the validity window, defined as
// ValidFrom ≤ t < ValidUntil (a zero ValidFrom is no lower bound, a zero
// ValidUntil is open-ended). The window is half-open so a rule ending at
// exactly valid_until is expired; the caller supplies the clock instant —
// the domain never reads a clock.
func (r DecisionRule) AppliesAt(t time.Time) bool {
	if r.Revoked {
		return false
	}
	if !r.ValidFrom.IsZero() && t.Before(r.ValidFrom) {
		return false
	}
	if !r.ValidUntil.IsZero() && !t.Before(r.ValidUntil) {
		return false
	}
	return true
}
