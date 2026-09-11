-- 00015_i6_retention_role.sql — dedicated retention database role (ARCH-007
-- §7 control 3a amendment, 2026-09-11 / DEV-128).
--
-- The governed retention and pseudonymisation acts (ARCH-007 §2/§3) delete and
-- redact rows the append-only application role may not touch: risksignal_app
-- (00013/00014) is append-only on audit_events and holds no DELETE on the
-- signal timeline. Running retention as the application role would therefore
-- either fail or force that role to be widened — removing the append-only
-- guarantee. This migration instead creates a separate, least-privilege
-- retention role with its own connection:
--
--   risksignal_retention        NOLOGIN group role: the retention grants.
--   risksignal_retention_login  LOGIN role: granted risksignal_retention. The
--                               operator injects its password at runtime (no
--                               password lives in a migration, ch. 3.3) and
--                               connects with it (database.retention_url). It
--                               is NEVER granted to the runtime login and
--                               retention never uses SET ROLE: the dedicated
--                               connection authenticates as this login.
--
-- The grant matrix is the minimum the retention/pseudonymisation statements of
-- db/queries/retention.sql issue, traced table by table. PostgreSQL checks
-- SELECT on the columns a statement reads, including those named in an
-- UPDATE/DELETE WHERE clause, so the SELECT granted alongside the delete
-- privileges below is load-bearing (not a convenience): without it the first
-- `DELETE ... WHERE signal_id = …` fails with SQLSTATE 42501 even though the
-- DELETE privilege is held.
--
--   audit_events    SELECT, INSERT, UPDATE, DELETE  (the retention.* append,
--                           the §2.3 delete of a signal's trail and the §3
--                           redaction of actor display names / snapshots)
--   risk_signals    SELECT, UPDATE, DELETE
--   comments        SELECT, UPDATE, DELETE
--   sla_clocks      SELECT, DELETE
--   matches         SELECT, DELETE
--   notifications   SELECT, DELETE
--   retention_runs  SELECT, UPDATE
--   legal_holds     SELECT
--
-- Everything else stays revoked: nothing on users, outbox, epss_current or
-- schema_migration_log; no TRUNCATE/REFERENCES/TRIGGER on any table; no CREATE
-- on public; not a superuser. The role reaches public through PUBLIC's default
-- USAGE grant only, and no ALTER DEFAULT PRIVILEGES is set for it (unlike
-- risksignal_app in 00013): the retention role has no business with tables the
-- retention statements do not name.
--
-- Re-running is a no-op — duplicate_object is swallowed and every GRANT/REVOKE
-- is idempotent — so parallel migrations on throwaway databases cannot race
-- (the convention of 00013/00014). The grant/revoke matrix is asserted by the
-- retention-role integration test (internal/adapters/postgres/repo), which also
-- proves risksignal_app still gets SQLSTATE 42501 when it tries to rewrite the
-- audit trail.
--
-- No Down migration: migrations are forward-only (ch. 7.4); rollbacks run the
-- previous application image, not SQL.

-- +goose Up

-- The retention group role and its dedicated login, created idempotently so a
-- fresh database and an existing one converge. The DO block carries
-- semicolons, so goose's statement splitter needs the StatementBegin/End
-- annotations.
-- +goose StatementBegin
DO $$
BEGIN
    BEGIN
        CREATE ROLE risksignal_retention NOLOGIN;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;
    BEGIN
        CREATE ROLE risksignal_retention_login LOGIN;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END;
END
$$;
-- +goose StatementEnd

-- The dedicated login carries the retention group role and nothing else. The
-- password is runtime-injected (database.retention_url); the runtime login is
-- deliberately not a member. Idempotent.
GRANT risksignal_retention TO risksignal_retention_login;

-- Start from a clean slate on the tables the retention role touches, so a
-- re-run (or a stray wider grant) converges to exactly the matrix below.
REVOKE ALL ON
    audit_events, comments, risk_signals, sla_clocks, matches,
    notifications, retention_runs, legal_holds
    FROM risksignal_retention;

-- The retention write/read matrix, grouped by the distinct privilege sets.
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_events TO risksignal_retention;
GRANT SELECT, UPDATE, DELETE ON risk_signals, comments TO risksignal_retention;
GRANT SELECT, DELETE ON sla_clocks, matches, notifications TO risksignal_retention;
GRANT SELECT, UPDATE ON retention_runs TO risksignal_retention;
GRANT SELECT ON legal_holds TO risksignal_retention;

-- Explicit non-grants (belt and braces, asserted by the integration test): the
-- tables the retention role must never touch at all, and the DDL-ish privileges
-- it must never hold. REVOKE is idempotent, so a re-run stays a no-op.
REVOKE ALL ON users, outbox, epss_current, schema_migration_log FROM risksignal_retention;
REVOKE TRUNCATE, REFERENCES, TRIGGER ON
    audit_events, comments, risk_signals, sla_clocks, matches,
    notifications, retention_runs, legal_holds
    FROM risksignal_retention;
REVOKE CREATE ON SCHEMA public FROM risksignal_retention;

COMMENT ON ROLE risksignal_retention IS
    'Governed retention/pseudonymisation group role (ARCH-007 §7 control 3a amendment): on audit_events SELECT/INSERT/UPDATE/DELETE; risk_signals SELECT/UPDATE/DELETE; comments SELECT/UPDATE/DELETE; sla_clocks/matches/notifications SELECT/DELETE; retention_runs SELECT/UPDATE; legal_holds SELECT — nothing else, no DDL, no TRUNCATE/REFERENCES/TRIGGER';
COMMENT ON ROLE risksignal_retention_login IS
    'Dedicated retention login (ARCH-007 §7 control 3a amendment): granted risksignal_retention; the retention connection authenticates as it (database.retention_url), never the runtime login and never via SET ROLE';
