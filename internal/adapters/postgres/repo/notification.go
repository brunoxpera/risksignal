package repo

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// NotificationRepo is the postgres implementation of the I4 notification
// delivery state (notifications.sql, ARCH-004 §6.2, WP-4.03 / DEV-073): the
// idempotent insert keyed on (outbox_event_id, channel), the delivery-state
// update and the per-signal read. The relay handler and NotifyPort adapters
// that drive it land with WP-4.06; this adapter owns the persistence shape.
//
// The methods return the generated row type because the typed notification
// read model (domain/application) arrives with the notification use cases
// (WP-4.06) — WP-4.03 only owns the query/adapter layer.
type NotificationRepo struct {
	q *gen.Queries
}

// NewNotificationRepo binds the repository to one query set.
func NewNotificationRepo(q *gen.Queries) *NotificationRepo { return &NotificationRepo{q: q} }

// Insert stores one notification row on the caller's transaction and reports
// whether it was newly inserted. The UQ (outbox_event_id, channel) makes the
// insert idempotent: a redelivery conflicts and ON CONFLICT DO NOTHING
// stores nothing, so inserted = false and no row is returned — exactly one
// notification per (event, channel) (FR-023). status is the initial delivery
// state ('pending' on the create path), createdAt the injected clock.
func (r *NotificationRepo) Insert(ctx context.Context, tx application.Tx, signalID, channel, kind, recipient, status, outboxEventID string, createdAt time.Time) (gen.Notification, bool, error) {
	const op = "notifications.insert"

	uid, err := toUUID(signalID)
	if err != nil {
		return gen.Notification{}, false, application.ValidationError(op, err)
	}
	if outboxEventID == "" {
		return gen.Notification{}, false, application.Validationf(op, "outbox_event_id is mandatory")
	}
	row, err := r.q.WithTx(tx).InsertNotification(ctx, gen.InsertNotificationParams{
		SignalID:      uid,
		Channel:       channel,
		Kind:          kind,
		Recipient:     toTextOpt(recipient),
		Status:        status,
		Attempts:      0,
		OutboxEventID: outboxEventID,
		CreatedAt:     toTS(createdAt),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return gen.Notification{}, false, nil
		}
		return gen.Notification{}, false, mapDBError(op, err)
	}
	return row, true, nil
}

// UpdateDelivery records the delivery receipt of one notification by its id:
// the new status, the attempt count, the last error text ("" clears it) and
// the delivered instant (nil clears it). A missing notification is a
// not-found error.
func (r *NotificationRepo) UpdateDelivery(ctx context.Context, tx application.Tx, id, status string, attempts int, lastError string, deliveredAt *time.Time) (gen.Notification, error) {
	const op = "notifications.update_delivery"

	uid, err := toUUID(id)
	if err != nil {
		return gen.Notification{}, application.ValidationError(op, err)
	}
	if attempts < 0 || attempts > math.MaxInt32 {
		return gen.Notification{}, application.Validationf(op, "attempts %d outside the int32 range", attempts)
	}
	row, err := r.q.WithTx(tx).UpdateNotificationDelivery(ctx, gen.UpdateNotificationDeliveryParams{
		Status:      status,
		Attempts:    int32(attempts),
		LastError:   toTextOpt(lastError),
		DeliveredAt: toTSPtrPtr(deliveredAt),
		ID:          uid,
	})
	if err != nil {
		return gen.Notification{}, mapDBError(op, err)
	}
	return row, nil
}

// ListBySignal returns a signal's notifications ordered by created_at then
// id. A signal without notifications yields an empty slice, never an error.
func (r *NotificationRepo) ListBySignal(ctx context.Context, signalID string) ([]gen.Notification, error) {
	const op = "notifications.list_by_signal"

	uid, err := toUUID(signalID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	rows, err := r.q.ListNotificationsBySignal(ctx, uid)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	return rows, nil
}
