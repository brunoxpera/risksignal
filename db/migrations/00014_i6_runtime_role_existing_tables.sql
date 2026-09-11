-- 00014_i6_runtime_role_existing_tables.sql — least-privilege grants for the
-- application runtime role on the pre-existing schema (ARCH-007 §7 control
-- 3a, WP-6.10 / DEV-126).
--
-- Migration 00013 is the control of record for the append-only audit trail: it
-- created the two NOLOGIN group roles risksignal_app and risksignal_migrator
-- and restricted audit_events to SELECT + INSERT. Its ALTER DEFAULT PRIVILEGES
-- statements, however, only cover objects created AFTER it runs — the ~26
-- tables the earlier migrations built (sources … risk_signals, outbox, users …
-- exports) were left with no privilege at all for risksignal_app. A runtime
-- login granted only risksignal_app therefore could not read or write the
-- domain tables and could not boot the server or worker (DEV-123 review
-- finding #3): the documented "connect as the runtime login" flow
-- (docs/operations/security-hardening.md) was broken for any pre-existing
-- schema.
--
-- This forward-only, re-runnable migration closes that gap: it grants
-- risksignal_app exactly the privileges the repository/query layer
-- (db/queries/*.sql, executed through internal/adapters/postgres) issues
-- against each existing table — nothing more. It grants no DDL, no schema
-- CREATE/USAGE (the role already reaches the public schema through PUBLIC's
-- default USAGE grant), no TRIGGER and no REFERENCES, and it does not widen
-- the append-only audit_events restriction: SELECT + INSERT stay, UPDATE /
-- DELETE / TRUNCATE stay denied (00013 remains the control of record).
--
-- The grant matrix, traced from db/queries (SELECT = read, INSERT / UPDATE /
-- DELETE = the writes the use cases issue, TRUNCATE = the atomic EPSS swap):
--
--   SELECT, INSERT, UPDATE, DELETE   comments, notifications, risk_signals,
--                                    sla_clocks
--   SELECT, INSERT, DELETE           matches, user_roles
--   SELECT, INSERT, UPDATE           alias_rules, assets, components,
--                                    decision_rules, exports,
--                                    inventory_imports, legal_holds, outbox,
--                                    quarantine, retention_runs, source_runs,
--                                    sources, users, vulnerabilities
--   SELECT, INSERT, TRUNCATE         epss_current
--   SELECT, INSERT                   evidences, raw_records, priority_rules,
--                                    epss_history
--   SELECT, INSERT                   audit_events (unchanged from 00013)
--   (none)                           schema_migration_log — migration
--                                    bookkeeping, written by
--                                    risksignal_migrator, never by the runtime
--
-- There are no sequences to grant: every primary key is a uuid column
-- defaulted to gen_random_uuid() (migration 00002 header), so the schema owns
-- no serial/identity sequence and ANALYZE/nextval privileges are moot.
--
-- Re-running is a no-op (every GRANT/REVOKE is idempotent) and the roles are
-- (re)created with duplicate_object swallowed, so parallel migrations on
-- throwaway databases cannot race — the same convention as 00013.
--
-- No Down migration: migrations are forward-only (ch. 7.4); rollbacks run the
-- previous application image, not SQL.

-- +goose Up

-- The two roles exist since 00013; recreate them idempotently so this
-- migration converges on any database and stays re-runnable. The DO block
-- carries semicolons, so goose's statement splitter needs the
-- StatementBegin/End annotations.
-- +goose StatementBegin
DO $$
BEGIN
    BEGIN
        CREATE ROLE risksignal_app NOLOGIN;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;
    BEGIN
        CREATE ROLE risksignal_migrator NOLOGIN;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;
END
$$;
-- +goose StatementEnd

-- The application role reads and writes the domain tables. The privilege set
-- per table is exactly what db/queries issues; grouped so the matrix above
-- reads one line per distinct set.

-- SELECT + INSERT + UPDATE + DELETE — the signal timeline and its governed
-- retention/pseudonymisation redaction paths: reads, the guarded lifecycle
-- writes (status/target/sla), the notification delivery stamps and the
-- redact-in-place / §2.3 deletion of a signal's dependents.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    comments, notifications, risk_signals, sla_clocks
    TO risksignal_app;

-- SELECT + INSERT + DELETE — the match rows (insert + the §2.3 delete) and the
-- user-role grants (grant, list, revoke; role rows are never updated).
GRANT SELECT, INSERT, DELETE ON
    matches, user_roles
    TO risksignal_app;

-- SELECT + INSERT + UPDATE — the inventory/inventory-matching tables, the
-- versioned rulesets, the governed operations tables and the outbox: reads
-- plus the upserts (ON CONFLICT DO UPDATE), the enable/revoke/ack transparent
-- transitions and the relay claim/ack lifecycle.
GRANT SELECT, INSERT, UPDATE ON
    alias_rules, assets, components, decision_rules, exports,
    inventory_imports, legal_holds, outbox, quarantine, retention_runs,
    source_runs, sources, users, vulnerabilities
    TO risksignal_app;

-- SELECT + INSERT + TRUNCATE — the current EPSS set: the load path swaps the
-- whole day atomically (TRUNCATE + COPY) inside one transaction, so the
-- runtime needs TRUNCATE (a privilege distinct from DELETE) as well as the
-- read and the bulk insert.
GRANT SELECT, INSERT, TRUNCATE ON
    epss_current
    TO risksignal_app;

-- SELECT + INSERT — the immutable/append-only tables the runtime only reads
-- and appends to: the source statements (evidences), the raw documents
-- (raw_records), the published priority-rules snapshots (priority_rules) and
-- the EPSS history (epss_history).
GRANT SELECT, INSERT ON
    evidences, raw_records, priority_rules, epss_history
    TO risksignal_app;

-- Belt and braces: audit_events stays append-only (00013 is the control of
-- record). Re-assert exactly SELECT + INSERT and revoke everything a wider
-- grant could have leaked, so a regression in this migration cannot widen the
-- audit write surface.
REVOKE ALL ON audit_events FROM risksignal_app;
GRANT SELECT, INSERT ON audit_events TO risksignal_app;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON audit_events FROM risksignal_app;
