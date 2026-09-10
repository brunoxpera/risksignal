package repo

// EpssHistoryRepo is the postgres implementation of the append-only
// epss_history write (ARCH-003 §7, ADR-013, WP-3.03b/WP-3.10): the
// application-level EpssHistoryLoader appends the observed history of the
// inventory-relevant CVEs of one EPSS run through it, on the pass
// transaction the daily-set swap commits on. History has no foreign keys
// onto epss_current (ADR-013: the current set is replaced whole by TRUNCATE
// + COPY; history survives its swaps by cve_id alone), so the append is a
// single idempotent INSERT with the natural-key ON CONFLICT DO NOTHING.

import (
	"context"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// EpssHistoryRepo implements application.EpssHistoryRepo over one query set.
type EpssHistoryRepo struct {
	q *gen.Queries
}

// NewEpssHistoryRepo binds the repository to one query set.
func NewEpssHistoryRepo(q *gen.Queries) *EpssHistoryRepo { return &EpssHistoryRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.EpssHistoryRepo = (*EpssHistoryRepo)(nil)

// Append implements application.EpssHistoryRepo: append one observed EPSS
// history row on the caller's transaction. observed_on is the run date
// (the injected clock instant, UTC); a repeated append of the same
// (cve_id, observed_on) day is a no-op (ON CONFLICT DO NOTHING), so a
// re-run of the same day never duplicates history.
func (r *EpssHistoryRepo) Append(ctx context.Context, tx application.Tx, rec application.EpssHistoryRecord) error {
	const op = "epss_history.append"

	err := r.q.WithTx(tx).AppendEpssHistory(ctx, gen.AppendEpssHistoryParams{
		CveID:        rec.CVEID,
		ObservedOn:   toDate(rec.ObservedOn),
		Score:        rec.Score,
		Percentile:   rec.Percentile,
		ModelVersion: rec.ModelVersion,
	})
	if err != nil {
		return mapDBError(op, err)
	}
	return nil
}
