package repo

import (
	"context"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
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

// GetByID implements application.AuditRepo: read one audit event by its id —
// the load step of the governed audit.reveal_identity act (ARCH-005 §7,
// ADR-014). It is a read; the table stays append-only. A missing id is a
// not-found Error (the reveal then writes nothing). The stored row is mapped
// onto the application-level AuditEvent (id and actor_display_name
// included); the before/after snapshots pass through as raw JSON.
func (r *AuditRepo) GetEventByID(ctx context.Context, id string) (application.AuditEvent, error) {
	const op = "audit.get_by_id"

	eid, err := toUUID(id)
	if err != nil {
		return application.AuditEvent{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetAuditEventByID(ctx, eid)
	if err != nil {
		return application.AuditEvent{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	return auditEventFromRow(row), nil
}

// auditEventFromRow maps a stored audit row onto the application-level
// AuditEvent (ch. 13.5: before/after stay minimised snapshots, no secrets).
func auditEventFromRow(row gen.AuditEvent) application.AuditEvent {
	return application.AuditEvent{
		ID:               uuidString(row.ID),
		AggregateType:    row.AggregateType,
		AggregateID:      uuidString(row.AggregateID),
		ActorType:        row.ActorType,
		ActorID:          row.ActorID,
		ActorDisplayName: textValue(row.ActorDisplayName),
		Action:           row.Action,
		OccurredAt:       tsTime(row.OccurredAt),
		Before:           row.Before,
		After:            row.After,
		CorrelationID:    row.CorrelationID,
	}
}
