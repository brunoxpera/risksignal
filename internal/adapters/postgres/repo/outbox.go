package repo

import (
	"context"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// OutboxRepo is the postgres implementation of application.OutboxRepo
// (outbox.sql, WP-1b.03). Append is the transactional write of the
// CreateSignal command — the ARCH-001 §5 fault seam — and runs on the
// caller's transaction: a failure here rolls the state change and the audit
// row back with it.
type OutboxRepo struct {
	q *gen.Queries
}

// NewOutboxRepo binds the repository to one query set.
func NewOutboxRepo(q *gen.Queries) *OutboxRepo { return &OutboxRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.OutboxRepo = (*OutboxRepo)(nil)

// Append implements application.OutboxRepo: append one pending outbox row on
// the caller's transaction (status 'pending', attempts 0, lease_until NULL —
// the column defaults and the statement's fixed status).
func (r *OutboxRepo) Append(ctx context.Context, tx application.Tx, ev application.OutboxEvent) error {
	const op = "outbox.append"

	_, err := r.q.WithTx(tx).AppendOutbox(ctx, gen.AppendOutboxParams{
		Type:        ev.Type,
		Payload:     ev.Payload,
		AvailableAt: toTS(ev.AvailableAt),
		DedupeKey:   ev.DedupeKey,
		CreatedAt:   toTS(ev.CreatedAt),
	})
	return mapDBError(op, err)
}

// ExistsDedupeKey implements application.OutboxRepo: report whether an
// outbox row with the dedupe key already exists on the caller's
// transaction (queued, claimed or terminal — the UQ spans the row's whole
// lifetime, ADR-012 point 4). The exactly-once enqueuers (the scheduler
// scan, the DEV-067 full-import fan-in) pre-check on the same transaction
// before appending: a duplicate INSERT would raise the unique violation
// and abort the transaction, so an idempotent re-enqueue is a pre-checked
// no-op.
func (r *OutboxRepo) ExistsDedupeKey(ctx context.Context, tx application.Tx, dedupeKey string) (bool, error) {
	const op = "outbox.exists_dedupe_key"

	exists, err := r.q.WithTx(tx).OutboxDedupeKeyExists(ctx, dedupeKey)
	if err != nil {
		return false, mapDBError(op, err)
	}
	return exists, nil
}
