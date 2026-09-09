package repo

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// MatchRepo is the postgres implementation of application.MatchRepo
// (matches.sql, ARCH-001 §3 step 4; I3 extension ARCH-003 §3): the
// method-led match insert, idempotent on the natural key (vulnerability_id,
// component_id, rule_version), carrying the decision-rule state (reasons,
// decision_rule_id, the auto_* override preservation).
type MatchRepo struct {
	q *gen.Queries
}

// NewMatchRepo binds the repository to one query set.
func NewMatchRepo(q *gen.Queries) *MatchRepo { return &MatchRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.MatchRepo = (*MatchRepo)(nil)

// Insert implements application.MatchRepo: record one method-led match on
// the caller's transaction and return its id — the newly inserted one, or
// the already existing one of an earlier run. A purely computed record
// (no reasons, no decision rule, no auto_*) persists reasons '[]' and NULL
// auto_* — the schema defaults of the 00005 extension; an override record
// persists the raw computed triple in auto_method/auto_confidence/
// auto_score (ADR-015, ARCH-003 §3).
func (r *MatchRepo) Insert(ctx context.Context, tx application.Tx, rec application.MatchRecord, createdAt time.Time) (string, error) {
	const op = "match.insert"

	// matches.score and matches.auto_score are int32 columns; reject a
	// score the column cannot hold instead of silently truncating it.
	if rec.Score < math.MinInt32 || rec.Score > math.MaxInt32 {
		return "", application.Validationf(op, "score %d outside the int32 range", rec.Score)
	}
	if rec.AutoScore != nil && (*rec.AutoScore < math.MinInt32 || *rec.AutoScore > math.MaxInt32) {
		return "", application.Validationf(op, "auto_score %d outside the int32 range", *rec.AutoScore)
	}
	vulnID, err := toUUID(rec.VulnerabilityID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	componentID, err := toUUID(rec.ComponentID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	// reasons is a jsonb NOT NULL column whose default is '[]'; a purely
	// computed record persists that default explicitly (json.Marshal of a
	// nil slice would produce the JSON null, not the '[]' the domain
	// invariant demands — TR-007 reasons are never nil).
	reasons := []byte("[]")
	if len(rec.Reasons) > 0 {
		b, err := json.Marshal(rec.Reasons)
		if err != nil {
			return "", application.ValidationError(op, err)
		}
		reasons = b
	}
	// decision_rule_id: NULL (unset) or the referencing rule's id.
	var decisionRuleID pgtype.UUID
	if rec.DecisionRuleID != nil {
		id, err := toUUID(*rec.DecisionRuleID)
		if err != nil {
			return "", application.ValidationError(op, err)
		}
		decisionRuleID = id
	}
	// auto_*: set only when a decision rule overrode the match.
	var autoMethod, autoConfidence pgtype.Text
	if rec.AutoMethod != nil {
		autoMethod = pgtype.Text{String: string(*rec.AutoMethod), Valid: true}
	}
	if rec.AutoConfidence != nil {
		autoConfidence = pgtype.Text{String: string(*rec.AutoConfidence), Valid: true}
	}
	var autoScore pgtype.Int4
	if rec.AutoScore != nil {
		autoScore = pgtype.Int4{Int32: int32(*rec.AutoScore), Valid: true}
	}

	id, err := r.q.WithTx(tx).InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID,
		ComponentID:     componentID,
		Method:          string(rec.Method),
		Score:           int32(rec.Score),
		Confidence:      string(rec.Confidence),
		RuleVersion:     rec.RuleVersion,
		CreatedAt:       toTS(createdAt),
		Reasons:         reasons,
		DecisionRuleID:  decisionRuleID,
		AutoMethod:      autoMethod,
		AutoConfidence:  autoConfidence,
		AutoScore:       autoScore,
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(id), nil
}
