package repo

import (
	"context"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// AuditRepo is the postgres implementation of application.AuditRepo
// (audit_events.sql, WP-1b.03). The table is append-only; Append is its only
// write path and runs on the caller's transaction.
type AuditRepo struct {
	q *gen.Queries
}

// NewAuditRepo binds the repository to one query set.
func NewAuditRepo(q *gen.Queries) *AuditRepo { return &AuditRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.AuditRepo = (*AuditRepo)(nil)

// Append implements application.AuditRepo: insert one immutable audit row on
// the caller's transaction.
func (r *AuditRepo) Append(ctx context.Context, tx application.Tx, ev application.AuditEvent) error {
	const op = "audit.append"

	aggregateID, err := toUUID(ev.AggregateID)
	if err != nil {
		return application.ValidationError(op, err)
	}
	_, err = r.q.WithTx(tx).InsertAuditEvent(ctx, gen.InsertAuditEventParams{
		AggregateType:    ev.AggregateType,
		AggregateID:      aggregateID,
		ActorType:        ev.ActorType,
		ActorID:          ev.ActorID,
		ActorDisplayName: toTextOpt(ev.ActorDisplayName),
		Action:           ev.Action,
		OccurredAt:       toTS(ev.OccurredAt),
		Before:           ev.Before,
		After:            ev.After,
		CorrelationID:    ev.CorrelationID,
	})
	return mapDBError(op, err)
}
