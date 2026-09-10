package repo

import (
	"context"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// CommentRepo is the postgres implementation of the I4 append-only signal
// timeline (comments.sql, ARCH-004 §2.2, WP-4.03 / DEV-073): the insert and
// the ordered per-signal read. There is no update or delete path — a comment
// is never edited or deleted; the command layer (WP-4.04) writes the
// signal.commented audit event in the same transaction as the insert.
type CommentRepo struct {
	q *gen.Queries
}

// NewCommentRepo binds the repository to one query set.
func NewCommentRepo(q *gen.Queries) *CommentRepo { return &CommentRepo{q: q} }

// Add appends one comment to a signal on the caller's transaction and
// returns it. createdAt is the injected clock instant; the id is the
// database default. The signal_id foreign key guards the reference (a
// comment for an unknown signal is a validation error).
func (r *CommentRepo) Add(ctx context.Context, tx application.Tx, signalID, actorID, body string, createdAt time.Time) (domain.Comment, error) {
	const op = "comments.add"

	uid, err := toUUID(signalID)
	if err != nil {
		return domain.Comment{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).InsertComment(ctx, gen.InsertCommentParams{
		SignalID:  uid,
		ActorID:   actorID,
		Body:      body,
		CreatedAt: toTS(createdAt),
	})
	if err != nil {
		return domain.Comment{}, mapDBError(op, err)
	}
	return commentFromRow(row), nil
}

// ListBySignal returns the signal's comments ordered by created_at then id —
// the append-only timeline read. A signal without comments yields an empty
// slice, never an error.
func (r *CommentRepo) ListBySignal(ctx context.Context, signalID string) ([]domain.Comment, error) {
	const op = "comments.list_by_signal"

	uid, err := toUUID(signalID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	rows, err := r.q.ListCommentsBySignal(ctx, uid)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]domain.Comment, 0, len(rows))
	for _, row := range rows {
		out = append(out, commentFromRow(row))
	}
	return out, nil
}

// commentFromRow maps a stored comments row onto the domain value object
// (the created_at column is carried by the ordering, not the value).
func commentFromRow(row gen.Comment) domain.Comment {
	return domain.Comment{
		ID:       uuidString(row.ID),
		SignalID: uuidString(row.SignalID),
		ActorID:  row.ActorID,
		Body:     row.Body,
	}
}
