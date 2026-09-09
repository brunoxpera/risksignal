package repo

import (
	"context"
	"math"
	"time"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// MatchRepo is the postgres implementation of application.MatchRepo
// (matches.sql, ARCH-001 §3 step 4): the method-led match insert, idempotent
// on the natural key (vulnerability_id, component_id, rule_version).
type MatchRepo struct {
	q *gen.Queries
}

// NewMatchRepo binds the repository to one query set.
func NewMatchRepo(q *gen.Queries) *MatchRepo { return &MatchRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.MatchRepo = (*MatchRepo)(nil)

// Insert implements application.MatchRepo: record one method-led match on
// the caller's transaction and return its id — the newly inserted one, or
// the already existing one of an earlier run.
func (r *MatchRepo) Insert(ctx context.Context, tx application.Tx, rec application.MatchRecord, createdAt time.Time) (string, error) {
	const op = "match.insert"

	// matches.score is an int32 column; reject a score the column cannot
	// hold instead of silently truncating it.
	if rec.Score < math.MinInt32 || rec.Score > math.MaxInt32 {
		return "", application.Validationf(op, "score %d outside the int32 range", rec.Score)
	}
	vulnID, err := toUUID(rec.VulnerabilityID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	componentID, err := toUUID(rec.ComponentID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	id, err := r.q.WithTx(tx).InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID,
		ComponentID:     componentID,
		Method:          string(rec.Method),
		Score:           int32(rec.Score),
		Confidence:      string(rec.Confidence),
		RuleVersion:     rec.RuleVersion,
		CreatedAt:       toTS(createdAt),
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(id), nil
}
