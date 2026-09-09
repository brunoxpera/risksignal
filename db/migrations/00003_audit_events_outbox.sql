-- 00003_audit_events_outbox.sql — audit trail + transactional outbox (ARCH-001
-- §1 and §2, WP-1b.03).
--
-- Creates the two tables that carry the ch. 5.1 invariant out of the domain
-- transaction: audit_events (append-only, ch. 13.1, ADR-014) and outbox (the
-- transactional outbox / job queue, ch. 7.1 "jobs / outbox", ch. 5.1, 7.3).
-- Columns, types, constraints and indexes match ARCH-001 §1 verbatim.
--
-- Identifier rules (implementation concept ch. 7.2, ARCH-001 §1): uuid
-- primary keys via gen_random_uuid() (core PostgreSQL since 13; the
-- environment runs postgres:16), every timestamp timestamptz. Neither table
-- carries a foreign key: audit_events.aggregate_id is polymorphic (points at
-- whatever aggregate the event describes), and outbox rows reference only
-- their immutable id, so the relay stays decoupled from the domain tables.
--
-- audit_events is append-only: no application path updates or deletes it
-- (the production DB role gets no write grant beyond INSERT/SELECT from I6);
-- before/after carry minimised state snapshots without secrets (ch. 13.5,
-- ADR-014). outbox carries integration events and, from I2/I4, job types;
-- the type column discriminates. status CHECK and the relay mechanics
-- (claim/ack/dead-letter) are ARCH-001 §2.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- audit_events — append-only audit trail (ch. 13.1, ADR-014). One row per
-- state-changing action, written atomically with the state change inside
-- WithTx (ARCH-001 §2). actor_type is 'system' in I1b and 'user' from I5a;
-- before/after are minimised snapshots (no secrets), occurred_at comes from
-- the injected clock. IX (aggregate_type, aggregate_id) serves the
-- per-aggregate history read; IX (occurred_at) the time-ordered trail.
CREATE TABLE audit_events (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type     text        NOT NULL,
    aggregate_id       uuid        NOT NULL,
    actor_type         text        NOT NULL,
    actor_id           text        NOT NULL,
    actor_display_name text        NULL,
    action             text        NOT NULL,
    occurred_at        timestamptz NOT NULL,
    before             jsonb       NULL,
    after              jsonb       NULL,
    correlation_id     text        NOT NULL
);

CREATE INDEX audit_events_aggregate_type_aggregate_id_idx ON audit_events (aggregate_type, aggregate_id);
CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);

COMMENT ON TABLE audit_events IS
    'Append-only audit trail (ch. 13.1, ADR-014): one immutable row per state-changing action, written atomically with the change (ARCH-001 §1)';
COMMENT ON COLUMN audit_events.aggregate_type IS
    'Type of the changed aggregate, e.g. risk_signal';
COMMENT ON COLUMN audit_events.aggregate_id IS
    'UUID of the changed aggregate (polymorphic — no FK, the aggregate type disambiguates)';
COMMENT ON COLUMN audit_events.actor_type IS
    'Principal kind: system in I1b (e.g. synthetic-source, demo-seed); user from I5a';
COMMENT ON COLUMN audit_events.actor_display_name IS
    'Display name at event time; cleared by the ADR-014 pseudonymisation stage, never relied on for identity';
COMMENT ON COLUMN audit_events.action IS
    'Action name, e.g. signal.created';
COMMENT ON COLUMN audit_events.occurred_at IS
    'Event time from the injected clock (never the DB wall clock)';
COMMENT ON COLUMN audit_events.before IS
    'Minimised state snapshot before the change, NULL for creates (ch. 13.5; no secrets)';
COMMENT ON COLUMN audit_events.after IS
    'Minimised state snapshot after the change (ch. 13.5; no secrets)';
COMMENT ON COLUMN audit_events.correlation_id IS
    'Request/command correlation id linking the audit row to the outbox row of the same command';

-- outbox — the transactional outbox / job queue (ch. 7.1, 5.1, 7.3). One
-- physical table carries integration events (the I1b case, type
-- 'signal.created') and, from I2/I4, background job types; the type column
-- discriminates. Rows are written in the same transaction as the state
-- change they announce; the relay claims them with a bounded, lease-based
-- UPDATE ... FOR UPDATE SKIP LOCKED and acks claimed -> done (ARCH-001 §2).
-- UQ (dedupe_key) stays unique for the whole lifetime of the row (ADR-012
-- consequence, ch. 14.2): a retried command cannot enqueue twice.
CREATE TABLE outbox (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    type          text        NOT NULL,
    payload       jsonb       NOT NULL,
    status        text        NOT NULL,
    available_at  timestamptz NOT NULL,
    lease_until   timestamptz NULL,
    attempts      integer     NOT NULL DEFAULT 0,
    last_error    text        NULL,
    dedupe_key    text        NOT NULL,
    created_at    timestamptz NOT NULL,
    CONSTRAINT outbox_status_check CHECK (status IN ('pending', 'claimed', 'done', 'dead_letter')),
    CONSTRAINT outbox_dedupe_key_key UNIQUE (dedupe_key)
);

CREATE INDEX outbox_status_available_at_idx ON outbox (status, available_at);

COMMENT ON TABLE outbox IS
    'Transactional outbox / job queue (ch. 7.1, 5.1, 7.3): one row per integration event or background job, written atomically with its state change (ARCH-001 §1)';
COMMENT ON COLUMN outbox.type IS
    'Row discriminator: event or job type, e.g. signal.created';
COMMENT ON COLUMN outbox.payload IS
    'Event/job payload: { event_id, type, signal_id, match_id, cve_id, priority, occurred_at, correlation_id } for signal.created';
COMMENT ON COLUMN outbox.status IS
    'pending -> claimed -> done | dead_letter (ARCH-001 §2); claimed rows are re-claimable once lease_until passes';
COMMENT ON COLUMN outbox.available_at IS
    'Earliest time the row may be claimed; scheduled/job rows set it in the future';
COMMENT ON COLUMN outbox.lease_until IS
    'Crash-recovery lease (TAT-05): NULL while pending, set by every claim, expiry makes the row re-claimable';
COMMENT ON COLUMN outbox.attempts IS
    'Delivery attempts; incremented by every claim (relay may dead-letter past the ch. 14.2 attempt cap)';
COMMENT ON COLUMN outbox.last_error IS
    'Error text of the failed delivery that led to dead_letter';
COMMENT ON COLUMN outbox.dedupe_key IS
    'Command-level idempotency key, e.g. signal.created:<signal_id>; unique for the row lifetime (ADR-012 consequence)';
COMMENT ON COLUMN outbox.created_at IS
    'Row creation time from the injected clock (never the DB wall clock)';
