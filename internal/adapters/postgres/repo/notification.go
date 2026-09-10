package repo

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// NotificationRepo is the postgres implementation of the I4 notification
// delivery state (notifications.sql, ARCH-004 §6.2, WP-4.03 / WP-4.06): the
// idempotent insert keyed on (outbox_event_id, channel), the by-key read a
// redelivery uses, the delivery-state update and the per-signal read. It
// implements the application.NotificationRepo port and maps the stored rows
// onto the application-level Notification value type — the application layer
// never imports the generated gen package (.go-arch-lint.yml).
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
func (r *NotificationRepo) Insert(ctx context.Context, tx application.Tx, signalID, channel, kind, recipient, status, outboxEventID string, createdAt time.Time) (application.Notification, bool, error) {
	const op = "notifications.insert"

	uid, err := toUUID(signalID)
	if err != nil {
		return application.Notification{}, false, application.ValidationError(op, err)
	}
	if outboxEventID == "" {
		return application.Notification{}, false, application.Validationf(op, "outbox_event_id is mandatory")
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
			return application.Notification{}, false, nil
		}
		return application.Notification{}, false, mapDBError(op, err)
	}
	return notificationFromRow(row), true, nil
}

// GetByEventChannel returns the one notification of an (outbox_event_id,
// channel) pair and whether it exists. A missing row is (zero, false, nil) —
// not an error: the relay handler treats a redelivery with no stored row as
// the fresh-insert case. It runs on the caller's transaction.
func (r *NotificationRepo) GetByEventChannel(ctx context.Context, tx application.Tx, outboxEventID, channel string) (application.Notification, bool, error) {
	const op = "notifications.get_by_event_channel"

	if outboxEventID == "" {
		return application.Notification{}, false, application.Validationf(op, "outbox_event_id is mandatory")
	}
	row, err := r.q.WithTx(tx).GetNotificationByEventChannel(ctx, gen.GetNotificationByEventChannelParams{
		OutboxEventID: outboxEventID,
		Channel:       channel,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return application.Notification{}, false, nil
		}
		return application.Notification{}, false, mapDBError(op, err)
	}
	return notificationFromRow(row), true, nil
}

// UpdateDelivery records the delivery receipt of one notification by its id:
// the new status, the attempt count, the last error text ("" clears it) and
// the delivered instant (nil clears it). A missing notification is a
// not-found error.
func (r *NotificationRepo) UpdateDelivery(ctx context.Context, tx application.Tx, id, status string, attempts int, lastError string, deliveredAt *time.Time) (application.Notification, error) {
	const op = "notifications.update_delivery"

	uid, err := toUUID(id)
	if err != nil {
		return application.Notification{}, application.ValidationError(op, err)
	}
	if attempts < 0 || attempts > math.MaxInt32 {
		return application.Notification{}, application.Validationf(op, "attempts %d outside the int32 range", attempts)
	}
	row, err := r.q.WithTx(tx).UpdateNotificationDelivery(ctx, gen.UpdateNotificationDeliveryParams{
		Status:      status,
		Attempts:    int32(attempts),
		LastError:   toTextOpt(lastError),
		DeliveredAt: toTSPtrPtr(deliveredAt),
		ID:          uid,
	})
	if err != nil {
		return application.Notification{}, mapDBError(op, err)
	}
	return notificationFromRow(row), nil
}

// ListBySignal returns a signal's notifications ordered by created_at then
// id. A signal without notifications yields an empty slice, never an error.
func (r *NotificationRepo) ListBySignal(ctx context.Context, signalID string) ([]application.Notification, error) {
	const op = "notifications.list_by_signal"

	uid, err := toUUID(signalID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	rows, err := r.q.ListNotificationsBySignal(ctx, uid)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.Notification, len(rows))
	for i, row := range rows {
		out[i] = notificationFromRow(row)
	}
	return out, nil
}

// notificationFromRow maps a stored notifications row onto the
// application-level value type: the canonical uuid strings, the nullable
// recipient/error as "" and the absent delivered_at as nil (the "not
// delivered" sentinel the delivery state machine reads).
func notificationFromRow(row gen.Notification) application.Notification {
	return application.Notification{
		ID:            uuidString(row.ID),
		SignalID:      uuidString(row.SignalID),
		Channel:       row.Channel,
		Kind:          row.Kind,
		Recipient:     textOr(row.Recipient),
		Status:        row.Status,
		Attempts:      int(row.Attempts),
		LastError:     textOr(row.LastError),
		DeliveredAt:   timePtr(row.DeliveredAt),
		OutboxEventID: row.OutboxEventID,
		CreatedAt:     tsTime(row.CreatedAt),
	}
}

// textOr renders a nullable text column as "" when NULL.
func textOr(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// timePtr renders a nullable timestamptz column as nil when NULL — the
// delivered_at "not yet delivered" sentinel.
func timePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	at := t.Time
	return &at
}
