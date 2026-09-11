package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// AuditRepo is the postgres implementation of application.AuditRepo
// (audit_events.sql, WP-1b.03). The table is append-only; Append is its only
// write path and runs on the caller's transaction.
type AuditRepo struct {
	q         *gen.Queries
	hashChain bool // retention.hash_chain_enabled: stamp prev_hash/row_hash
}

// NewAuditRepo binds the repository to one query set (hash chain disabled).
func NewAuditRepo(q *gen.Queries) *AuditRepo { return &AuditRepo{q: q} }

// NewAuditRepoWithHashChain binds the repository and enables the optional
// audit hash chain (retention.hash_chain_enabled, ARCH-007 §7 control 3b).
// When enabled, Append stamps prev_hash/row_hash in the same transaction and
// takes the chain's advisory lock; when disabled the append path is
// unchanged.
func NewAuditRepoWithHashChain(q *gen.Queries, enabled bool) *AuditRepo {
	return &AuditRepo{q: q, hashChain: enabled}
}

// compile-time check that the repository satisfies its port.
var _ application.AuditRepo = (*AuditRepo)(nil)

// Append implements application.AuditRepo: insert one immutable audit row on
// the caller's transaction. With the optional hash chain enabled
// (retention.hash_chain_enabled) the row's prev_hash/row_hash are computed in
// the same transaction (stampChain, ARCH-007 §7 control 3b); otherwise the
// append path is unchanged.
func (r *AuditRepo) Append(ctx context.Context, tx application.Tx, ev application.AuditEvent) error {
	const op = "audit.append"

	aggregateID, err := toUUID(ev.AggregateID)
	if err != nil {
		return application.ValidationError(op, err)
	}
	params := gen.InsertAuditEventParams{
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
	}
	if r.hashChain {
		if err := r.stampChain(ctx, tx, ev, aggregateID, &params); err != nil {
			return mapDBError(op, err)
		}
	}
	_, err = r.q.WithTx(tx).InsertAuditEvent(ctx, params)
	return mapDBError(op, err)
}

// stampChain computes the chain link of one row on the caller's transaction:
// it takes the chain's advisory lock (so concurrent chained appends cannot
// fork the chain), reads the latest row_hash, and sets prev_hash/row_hash =
// SHA-256(prev_hash ‖ canonical row bytes) on params.
func (r *AuditRepo) stampChain(ctx context.Context, tx application.Tx, ev application.AuditEvent, aggregateID pgtype.UUID, params *gen.InsertAuditEventParams) error {
	q := r.q.WithTx(tx)
	if err := q.AcquireAuditChainLock(ctx, auditChainLockKey); err != nil {
		return err
	}
	prev, err := q.LatestAuditHash(ctx)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		prev = pgtype.Text{} // first chained row: links to NULL
	}
	row := auditChainRow{
		AggregateType:    ev.AggregateType,
		AggregateID:      uuidString(aggregateID),
		ActorType:        ev.ActorType,
		ActorID:          ev.ActorID,
		ActorDisplayName: ev.ActorDisplayName,
		Action:           ev.Action,
		OccurredAt:       ev.OccurredAt,
		Before:           ev.Before,
		After:            ev.After,
		CorrelationID:    ev.CorrelationID,
	}
	params.PrevHash = prev
	params.RowHash = pgtype.Text{String: auditRowHash(textValue(prev), row), Valid: true}
	return nil
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

// ListByAggregate implements application.AuditRepo: read one aggregate's
// audit timeline ordered by occurred_at then id (ARCH-006 §3.1, DEV-110) —
// the signal-detail timeline read. It is a read over the append-only table
// (not a second write path) walking IX
// audit_events_aggregate_type_aggregate_id_idx; an aggregate with no event is
// an empty slice, never an error.
func (r *AuditRepo) ListByAggregate(ctx context.Context, aggregateType, aggregateID string) ([]application.AuditEvent, error) {
	const op = "audit.list_by_aggregate"

	id, err := toUUID(aggregateID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	rows, err := r.q.ListAuditEventsByAggregate(ctx, gen.ListAuditEventsByAggregateParams{
		AggregateType: aggregateType,
		AggregateID:   id,
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.AuditEvent, 0, len(rows))
	for _, row := range rows {
		out = append(out, auditEventFromRow(row))
	}
	return out, nil
}
