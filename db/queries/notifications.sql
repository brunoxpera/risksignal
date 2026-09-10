-- notifications: the notification delivery-state statements (ARCH-004 §6.2,
-- WP-4.03 / DEV-073).
--
-- One notification per (outbox_event_id, channel): the immutable outbox row
-- id is the channel idempotency key (ch. 14.3/15.3), so a redelivery
-- (lease expiry, at-least-once relay) is a no-op — exactly one notification
-- per event and channel (FR-023 "genau eine Benachrichtigung"). The relay
-- handler (WP-4.06) inserts the row pending, calls NotifyPort, then records
-- the receipt; delivery is post-commit and never rolls back the signal
-- state (ch. 5.1). This file only owns the persistence.

-- InsertNotification inserts one notification row and returns it. The
-- UQ (outbox_event_id, channel) makes the insert idempotent: a redelivery
-- conflicts and ON CONFLICT DO NOTHING stores nothing, so RETURNING yields
-- no row (the adapter reports "already inserted") — a duplicate delivery can
-- never create a second notification. status starts 'pending', attempts 0
-- (the row enters the delivery state machine pending); created_at is the
-- injected clock.
-- name: InsertNotification :one
INSERT INTO notifications (signal_id, channel, kind, recipient, status, attempts, outbox_event_id, created_at)
VALUES (@signal_id, @channel, @kind, @recipient, @status, @attempts, @outbox_event_id, @created_at)
ON CONFLICT (outbox_event_id, channel) DO NOTHING
RETURNING *;

-- UpdateNotificationDelivery records the delivery receipt of one notification
-- by its id: the new status, the attempt count, the last error text (NULL
-- while clean) and the delivered_at instant (NULL unless delivered). The
-- relay drives it after a NotifyPort.Deliver call; a redelivery that never
-- re-inserted the row cannot land here (there is nothing to update).
-- name: UpdateNotificationDelivery :one
UPDATE notifications SET
    status       = @status,
    attempts     = @attempts,
    last_error   = @last_error,
    delivered_at = @delivered_at
WHERE id = @id
RETURNING *;

-- GetNotificationByEventChannel returns the one notification of an
-- (outbox_event_id, channel) pair — the handler's read of a redelivered
-- event: it resolves whether the existing row is already delivered (a
-- no-op) or still pending after a temporary delivery failure (a retry),
-- without re-inserting. A missing row yields no row, never an error (the
-- insert path then proceeds).
-- name: GetNotificationByEventChannel :one
SELECT *
FROM notifications
WHERE outbox_event_id = @outbox_event_id AND channel = @channel;

-- ListNotificationsBySignal returns a signal's notifications ordered by
-- created_at then id (the IX notifications_signal_id index serves the
-- filter). The in-app surface (I5b) and the tests read it. A signal without
-- notifications yields no rows, never an error.
-- name: ListNotificationsBySignal :many
SELECT *
FROM notifications
WHERE signal_id = @signal_id
ORDER BY created_at, id;
