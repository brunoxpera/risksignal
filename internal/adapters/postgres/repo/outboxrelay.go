package repo

// OutboxRelay is the postgres implementation of the worker relay's store
// port (worker.OutboxStore, WP-1b.06): it runs the ARCH-001 §2 claim, ack
// and dead-letter statements of outbox.sql (WP-1b.03) against the real
// outbox table. ClaimBatch is the lease-based UPDATE ... FOR UPDATE SKIP
// LOCKED claim of the bounded due batch (pending rows plus claimed rows
// with an expired lease — the crash-recovery path, TAT-05); Ack and
// DeadLetter are the guarded terminal transitions (status='claimed'), so a
// double dispatch cannot double-ack and a terminal row is never overwritten
// (ARCH-001 §2). The relay owns the delivery semantics; this type only
// translates rows and driver errors.

import (
	"context"
	"math"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/worker"
	"github.com/xpera/risksignal/internal/application"
)

// OutboxRelay binds the claim/ack/dead-letter statements to one query set.
type OutboxRelay struct {
	q *gen.Queries
}

// NewOutboxRelay binds the relay store to one query set (the pool-scoped
// query set of the worker composition root).
func NewOutboxRelay(q *gen.Queries) *OutboxRelay { return &OutboxRelay{q: q} }

// compile-time check that the relay store satisfies its port.
var _ worker.OutboxStore = (*OutboxRelay)(nil)

// ClaimBatch implements worker.OutboxStore. limit must be positive (the
// worker drain always claims its bounded batch); the claim orders by
// available_at and id and skips rows other worker instances hold.
func (r *OutboxRelay) ClaimBatch(ctx context.Context, limit int) ([]worker.ClaimedEvent, error) {
	const op = "outbox.claim_batch"

	// ClaimOutboxBatch takes an int32 batch size; the worker claims a fixed
	// small batch, but the store still rejects a limit the column cannot
	// hold instead of silently truncating it.
	if limit <= 0 || limit > math.MaxInt32 {
		return nil, application.Validationf(op, "batch limit %d outside [1,%d]", limit, math.MaxInt32)
	}
	rows, err := r.q.ClaimOutboxBatch(ctx, int32(limit))
	if err != nil {
		return nil, mapDBError(op, err)
	}
	events := make([]worker.ClaimedEvent, 0, len(rows))
	for _, row := range rows {
		events = append(events, worker.ClaimedEvent{
			ID:       uuidString(row.ID),
			Type:     row.Type,
			Payload:  row.Payload,
			Attempts: int(row.Attempts),
		})
	}
	return events, nil
}

// Ack implements worker.OutboxStore: claimed -> done. The status='claimed'
// guard makes the ack idempotent — a row that is no longer claimed (already
// terminal) matches zero rows and is treated as already delivered, which is
// exactly the double-dispatch case of ARCH-001 §2.
func (r *OutboxRelay) Ack(ctx context.Context, id string) error {
	const op = "outbox.ack"

	uid, err := toUUID(id)
	if err != nil {
		return application.ValidationError(op, err)
	}
	if _, err := r.q.AckOutbox(ctx, uid); err != nil {
		return mapDBError(op, err)
	}
	return nil
}

// DeadLetter implements worker.OutboxStore: claimed -> dead_letter with the
// recorded error. Like the ack it is guarded by status='claimed' — only a
// row the relay currently holds can be dead-lettered.
func (r *OutboxRelay) DeadLetter(ctx context.Context, id, lastError string) error {
	const op = "outbox.dead_letter"

	if lastError == "" {
		return application.Validationf(op, "last error must not be empty")
	}
	uid, err := toUUID(id)
	if err != nil {
		return application.ValidationError(op, err)
	}
	if _, err := r.q.DeadLetterOutbox(ctx, gen.DeadLetterOutboxParams{
		ID:        uid,
		LastError: toTextOpt(lastError),
	}); err != nil {
		return mapDBError(op, err)
	}
	return nil
}
