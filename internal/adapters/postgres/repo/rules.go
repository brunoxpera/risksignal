package repo

// RuleRepo is the postgres implementation of the I3 rule-state reads
// (ARCH-003 §1.4/§3, WP-3.06/DEV-065): application.MatchingRuleRepo — the
// effective alias and decision rules of the current ruleset plus the two
// version counters a matching run evaluates under — and the narrower
// application.AliasRuleRepo (the enabled alias rules of the current
// ruleset version, the read the candidate pre-filter and the engine share
// when only the alias side is needed). Both read ports are satisfied by
// one type: the alias half is the identical read (ListEffectiveAliasRules
// of alias_rules.sql), the matching port adds the decision-rule half and
// the two version counters (GetLatestAliasRulesVersion /
// GetLatestDecisionRulesVersion — the COALESCE(max(version), 0) queries
// the inventory commit already reads through InventoryRepo.RuleVersions).
//
// The adapter is read-only — rule configuration writes are the future
// rule-management work package's write path; this type only ever SELECTs.
// Every read returns the domain rule values the engine consumes
// (domain.AliasRule / domain.DecisionRule, rebuilt through the domain
// constructors so a stored row that violates the ruleset contract — a
// self-loop, an invalid type, a rule shape the CRUD path would never have
// written — surfaces as a validation error of the run instead of
// poisoning a closure silently).

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// RuleRepo implements the rule-state reads of the matching runs over one
// query set.
type RuleRepo struct {
	q *gen.Queries
}

// NewRuleRepo binds the repository to one query set.
func NewRuleRepo(q *gen.Queries) *RuleRepo { return &RuleRepo{q: q} }

// compile-time checks that the repository satisfies both read ports.
var (
	_ application.MatchingRuleRepo = (*RuleRepo)(nil)
	_ application.AliasRuleRepo    = (*RuleRepo)(nil)
)

// Effective implements application.AliasRuleRepo: the enabled alias rules
// of the current ruleset version — exactly the alias half of
// EffectiveAliasRules.
func (r *RuleRepo) Effective(ctx context.Context) ([]domain.AliasRule, error) {
	return r.EffectiveAliasRules(ctx)
}

// EffectiveAliasRules implements application.MatchingRuleRepo: the enabled
// alias rules of the current ruleset (per (scope, from_value) the newest
// row that stands enabled — the standing rules the symmetric one-hop
// alias closure resolves over), sorted by scope then from_value for a
// deterministic read. A ruleset with no rules yields an empty slice,
// never an error.
func (r *RuleRepo) EffectiveAliasRules(ctx context.Context) ([]domain.AliasRule, error) {
	const op = "rules.effective_alias_rules"

	rows, err := r.q.ListEffectiveAliasRules(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]domain.AliasRule, 0, len(rows))
	for _, row := range rows {
		scope, err := domain.ParseAliasScope(row.Scope)
		if err != nil {
			return nil, application.ValidationError(op, fmt.Errorf("alias rule %s: %w", uuidString(row.ID), err))
		}
		rule, err := domain.NewAliasRule(uuidString(row.ID), scope, row.FromValue, row.ToValue, textValue(row.Reason), int(row.Version))
		if err != nil {
			return nil, application.ValidationError(op, fmt.Errorf("alias rule %s: %w", uuidString(row.ID), err))
		}
		if !rule.Enabled {
			// The query only returns enabled rows; a disabled row that
			// slipped through would be inert and must not reach the
			// closure (defensive — the SQL filter is the contract).
			continue
		}
		out = append(out, rule)
	}
	return out, nil
}

// EffectiveDecisionRules implements application.MatchingRuleRepo: every
// unrevoked decision rule of the current ruleset (ch. 9.2 — nothing but
// the explicit revocation supersedes a decision rule), ordered by id for
// a deterministic read (the engine re-sorts by (version, id) before
// applying the rules at match time). The rules carry their stored
// validity window and creation version verbatim; applicability is the
// engine's decision against the clock instant of the run
// (domain.DecisionRule.AppliesAt). A ruleset with no rules yields an
// empty slice, never an error.
func (r *RuleRepo) EffectiveDecisionRules(ctx context.Context) ([]domain.DecisionRule, error) {
	const op = "rules.effective_decision_rules"

	rows, err := r.q.ListEffectiveDecisionRules(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]domain.DecisionRule, 0, len(rows))
	for _, row := range rows {
		rule, err := decisionRuleFromRow(row)
		if err != nil {
			return nil, application.ValidationError(op, fmt.Errorf("decision rule %s: %w", uuidString(row.ID), err))
		}
		out = append(out, rule)
	}
	return out, nil
}

// AliasVersion implements application.MatchingRuleRepo: the current alias
// ruleset version counter — COALESCE(max(version), 0) of alias_rules —
// the "a<n>" half of the composite rule version the run's matches are
// stamped with (domain.RulesetVersion). An empty table reads 0.
func (r *RuleRepo) AliasVersion(ctx context.Context) (int, error) {
	const op = "rules.alias_version"

	v, err := r.q.GetLatestAliasRulesVersion(ctx)
	if err != nil {
		return 0, mapDBError(op, err)
	}
	return int(v), nil
}

// DecisionVersion implements application.MatchingRuleRepo: the current
// decision ruleset version counter — COALESCE(max(version), 0) of
// decision_rules — the "d<m>" half of the composite rule version. An
// empty table reads 0.
func (r *RuleRepo) DecisionVersion(ctx context.Context) (int, error) {
	const op = "rules.decision_version"

	v, err := r.q.GetLatestDecisionRulesVersion(ctx)
	if err != nil {
		return 0, mapDBError(op, err)
	}
	return int(v), nil
}

// decisionActionDTO is the stored action jsonb shape of an override rule
// ({"method": "…", "similarity": n} — the domain DecisionAction carries no
// json tags; the row mapping decodes through this DTO).
type decisionActionDTO struct {
	Method     string `json:"method"`
	Similarity int    `json:"similarity,omitempty"`
}

// decisionRuleFromRow rebuilds the domain decision rule value of one
// unrevoked decision_rules row (the SQL read returns unrevoked rows only,
// so the rule stands: Revoked false). The stored jsonb blocks decode into
// the domain target/action shapes (the write path of the future
// rule-management work package stores them canonically) and the domain
// constructor re-validates the whole rule — a row the CRUD path would
// never have written is surfaced as a validation error of the run.
func decisionRuleFromRow(row gen.DecisionRule) (domain.DecisionRule, error) {
	typ, err := domain.ParseDecisionRuleType(row.Type)
	if err != nil {
		return domain.DecisionRule{}, err
	}
	var target domain.DecisionTarget
	if err := json.Unmarshal(row.TargetScope, &target); err != nil {
		return domain.DecisionRule{}, fmt.Errorf("decode target_scope: %w", err)
	}
	var action *domain.DecisionAction
	if row.Action != nil {
		var dto decisionActionDTO
		if err := json.Unmarshal(row.Action, &dto); err != nil {
			return domain.DecisionRule{}, fmt.Errorf("decode action: %w", err)
		}
		method, err := domain.ParseMatchMethod(dto.Method)
		if err != nil {
			return domain.DecisionRule{}, err
		}
		action = &domain.DecisionAction{Method: method, Similarity: dto.Similarity}
	}
	return domain.NewDecisionRule(uuidString(row.ID), typ, target, action, row.Reason, row.ActorID, int(row.Version), tsTime(row.ValidFrom), tsTime(row.ValidUntil))
}
