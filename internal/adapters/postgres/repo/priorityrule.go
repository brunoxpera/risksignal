package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// PriorityRuleRepo is the postgres implementation of the I4 priority-rules
// persistence (priority_rules.sql, ARCH-004 §1, WP-4.03 / DEV-073): the
// copy-on-write snapshot publish, the effective-snapshot read and the
// effective-version read. The ruleset is a versioned data snapshot — a
// publish writes the whole P1..P4 rows at MAX(version)+1, the effective
// snapshot is WHERE version = MAX(version), and a signal references exactly
// one snapshot through its rule_version. The adapter reads stored rows back
// through the domain value object so a snapshot the publish path would never
// have written (an invalid predicate) surfaces as a validation error, not a
// poisoned evaluation.
type PriorityRuleRepo struct {
	q *gen.Queries
}

// NewPriorityRuleRepo binds the repository to one query set.
func NewPriorityRuleRepo(q *gen.Queries) *PriorityRuleRepo { return &PriorityRuleRepo{q: q} }

// Publish writes one full ruleset snapshot — the four rules P1..P4 of the
// passed slice, in order — at next = MAX(version)+1, all sharing one
// effectiveFrom/reason/actorID/createdAt. It returns the new effective
// version. The caller is the admin, audited PublishPriorityRules command
// (WP-4.04): reason and actorID are mandatory, the snapshot must carry
// exactly the four rules, and each rule is re-validated before it is stored.
func (r *PriorityRuleRepo) Publish(ctx context.Context, tx application.Tx, rules []domain.PriorityRule, effectiveFrom time.Time, reason, actorID string, createdAt time.Time) (int, error) {
	const op = "priority_rules.publish"

	if len(rules) != 4 {
		return 0, application.Validationf(op, "a ruleset snapshot must carry exactly 4 rules (P1..P4), got %d", len(rules))
	}
	if actorID == "" {
		return 0, application.Validationf(op, "actor_id is mandatory")
	}
	if effectiveFrom.IsZero() || createdAt.IsZero() {
		return 0, application.Validationf(op, "publish instants must not be zero")
	}
	defs := make([][]byte, 4)
	for i, rule := range rules {
		if err := rule.Validate(); err != nil {
			return 0, application.ValidationError(op, err)
		}
		b, err := json.Marshal(rule.Definition)
		if err != nil {
			return 0, application.InfraError(op, err)
		}
		defs[i] = b
	}
	versions, err := r.q.WithTx(tx).PublishPriorityRules(ctx, gen.PublishPriorityRulesParams{
		EffectiveFrom: toTS(effectiveFrom),
		Reason:        toTextOpt(reason),
		ActorID:       actorID,
		CreatedAt:     toTS(createdAt),
		P1RuleID:      string(rules[0].RuleID),
		P1Definition:  defs[0],
		P1Enabled:     rules[0].Enabled,
		P2RuleID:      string(rules[1].RuleID),
		P2Definition:  defs[1],
		P2Enabled:     rules[1].Enabled,
		P3RuleID:      string(rules[2].RuleID),
		P3Definition:  defs[2],
		P3Enabled:     rules[2].Enabled,
		P4RuleID:      string(rules[3].RuleID),
		P4Definition:  defs[3],
		P4Enabled:     rules[3].Enabled,
	})
	if err != nil {
		return 0, mapDBError(op, err)
	}
	if len(versions) == 0 {
		return 0, application.InfraError(op, fmt.Errorf("publish returned no version"))
	}
	return int(versions[0]), nil
}

// Effective returns the whole effective snapshot — the rules at
// MAX(version) — ordered by rule_id (P1→P4) and re-validated through the
// domain value object. Disabled rules are returned too (a disabled rule is
// inert; the evaluator skips it). An empty ruleset yields an empty slice,
// never an error.
func (r *PriorityRuleRepo) Effective(ctx context.Context) ([]domain.PriorityRule, error) {
	const op = "priority_rules.effective"

	rows, err := r.q.ListEffectivePriorityRules(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]domain.PriorityRule, 0, len(rows))
	for _, row := range rows {
		rule, err := priorityRuleFromRow(row)
		if err != nil {
			return nil, application.ValidationError(op, fmt.Errorf("priority rule %s v%d: %w", row.RuleID, row.Version, err))
		}
		out = append(out, rule)
	}
	return out, nil
}

// EffectiveVersion returns the current effective ruleset version
// (MAX(version), the snapshot in force). An empty table reads 0 — the
// "no ruleset published yet" sentinel the create path treats as "keep the
// I1b stamp" until the first publish (ARCH-004 §1).
func (r *PriorityRuleRepo) EffectiveVersion(ctx context.Context) (int, error) {
	const op = "priority_rules.effective_version"

	v, err := r.q.GetEffectivePriorityRulesVersion(ctx)
	if err != nil {
		return 0, mapDBError(op, err)
	}
	return int(v), nil
}

// priorityRuleFromRow rebuilds the domain priority rule of one snapshot row:
// the stored definition jsonb decodes into the bounded predicate tree and the
// domain value object re-validates the whole rule, so a stored rule the
// publish path would never have written is surfaced as an error rather than
// silently evaluated.
func priorityRuleFromRow(row gen.PriorityRule) (domain.PriorityRule, error) {
	var def domain.RuleDefinition
	if err := json.Unmarshal(row.Definition, &def); err != nil {
		return domain.PriorityRule{}, fmt.Errorf("decode definition: %w", err)
	}
	rule := domain.PriorityRule{
		RuleID:     domain.Priority(row.RuleID),
		Version:    int(row.Version),
		Definition: def,
		Enabled:    row.Enabled,
		Reason:     textValue(row.Reason),
		ActorID:    row.ActorID,
	}
	if err := rule.Validate(); err != nil {
		return domain.PriorityRule{}, err
	}
	return rule, nil
}
