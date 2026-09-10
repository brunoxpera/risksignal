-- 00008_i4_notifications.sql — I4 notification delivery state
-- (ARCH-004 §6.2, WP-4.03/4.06).
--
-- ARCH-004 §6.2 defines the notifications delivery-state table (one row per
-- (outbox_event_id, channel)), but the I4 schema migration 00007 (WP-4.02)
-- created only priority_rules, comments, sla_clocks and the risk_signals
-- extension. The WP-4.03 query scope (ARCH-004 WP-4.03 row) nevertheless
-- includes the notifications insert/update + UQ statements, so the table
-- must exist before sqlc can compile them: this forward-only migration adds
-- it verbatim from ARCH-004 §6.2. The NotifyPort adapters and the relay
-- handler that populate it land with WP-4.06; this migration only owns the
-- storage shape and its idempotency key.
--
-- Purely additive: no existing table, column or constraint changes meaning
-- (ADR-010). No Down migration: migrations are forward-only.

-- +goose Up

-- notifications (ARCH-004 §6.2, ch. 14.3): the delivery state of one
-- notification per (outbox_event_id, channel). The immutable outbox row id
-- is the channel idempotency key — a redelivery (lease expiry, at-least-
-- once) is a no-op, so exactly one notification is stored per (event,
-- channel) (FR-023 "genau eine Benachrichtigung"). status/attempts/
-- last_error/delivered_at are the delivery state; attempts is bounded by the
-- relay's maxAttempts. recipient is the SMTP/webhook target (config-derived;
-- NULL for the in-app surface). created_at is the injected clock insert
-- instant and orders the per-signal list; it is the one addition to the
-- ch. 6.2 column list (the timeline read needs a deterministic order).
CREATE TABLE notifications (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id       uuid        NOT NULL,
    channel         text        NOT NULL,
    kind            text        NOT NULL,
    recipient       text        NULL,
    status          text        NOT NULL,
    attempts        integer     NOT NULL DEFAULT 0,
    last_error      text        NULL,
    delivered_at    timestamptz NULL,
    outbox_event_id text        NOT NULL,
    created_at      timestamptz NOT NULL,
    CONSTRAINT notifications_signal_id_fkey FOREIGN KEY (signal_id) REFERENCES risk_signals (id),
    CONSTRAINT notifications_outbox_event_id_channel_key UNIQUE (outbox_event_id, channel),
    CONSTRAINT notifications_channel_check CHECK (channel IN ('in_app', 'smtp', 'webhook')),
    CONSTRAINT notifications_kind_check CHECK (kind IN ('signal.created', 'signal.escalated', 'signal.reopen_proposed', 'reminder')),
    CONSTRAINT notifications_status_check CHECK (status IN ('pending', 'delivered', 'failed'))
);

CREATE INDEX notifications_signal_id_idx ON notifications (signal_id);

COMMENT ON TABLE notifications IS
    'One notification per (outbox_event_id, channel) (ARCH-004 §6.2, ch. 14.3): the immutable outbox id is the channel idempotency key, so a redelivery is a no-op — exactly one notification per event and channel (FR-023)';
COMMENT ON COLUMN notifications.signal_id IS
    'The signal this notification concerns';
COMMENT ON COLUMN notifications.channel IS
    'Delivery channel: in_app | smtp | webhook (ARCH-004 §6.1)';
COMMENT ON COLUMN notifications.kind IS
    'Event kind: signal.created | signal.escalated | signal.reopen_proposed | reminder';
COMMENT ON COLUMN notifications.recipient IS
    'SMTP/webhook target (config-derived); NULL for the in-app surface';
COMMENT ON COLUMN notifications.status IS
    'Delivery state: pending | delivered | failed';
COMMENT ON COLUMN notifications.attempts IS
    'Delivery attempts so far; bounded by the relay maxAttempts (ch. 14.2)';
COMMENT ON COLUMN notifications.last_error IS
    'Last delivery error text (failed deliveries); NULL while clean';
COMMENT ON COLUMN notifications.delivered_at IS
    'When the delivery succeeded; NULL while pending/failed';
COMMENT ON COLUMN notifications.outbox_event_id IS
    'The immutable outbox row id — the channel idempotency key (UQ (outbox_event_id, channel), ch. 14.3)';
COMMENT ON COLUMN notifications.created_at IS
    'Insert instant from the injected clock; orders the per-signal list';
