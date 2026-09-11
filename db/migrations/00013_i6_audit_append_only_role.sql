-- 00013_i6_audit_append_only_role.sql — append-only audit DB role (ARCH-007
-- §7 control 3a, WP-6.10 / DEV-123).
--
-- The application runtime role may only INSERT/SELECT the append-only
-- audit_events table — no UPDATE, DELETE or TRUNCATE — so a compromised or
-- buggy application process cannot rewrite the audit trail; a separate
-- risksignal_migrator role owns schema changes. Both roles are created as
-- NOLOGIN group roles: the operator grants the app role to the runtime login
-- and the migrator role to the migration login (a password never lives in a
-- migration; deployment credentials are runtime-injected, ch. 3.3).
--
-- Re-running is a no-op — duplicate_object is swallowed, so parallel
-- migrations on throwaway databases cannot race — and every grant is
-- idempotent. This is the control of record for §7 control 3a; the test that
-- the app role is denied UPDATE/DELETE lives with the audit repository
-- integration tests.
--
-- No Down migration: migrations are forward-only (ch. 7.4); rollbacks run the
-- previous application image, not SQL.

-- +goose Up

-- The two roles of the append-only audit trail. Created idempotently so a
-- fresh database and an existing one converge. The DO block carries
-- semicolons, so goose's statement splitter needs the StatementBegin/End
-- annotations.
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

-- The application role: on the append-only audit trail exactly SELECT + INSERT.
REVOKE ALL ON audit_events FROM risksignal_app;
GRANT SELECT, INSERT ON audit_events TO risksignal_app;
-- Belt and braces: never UPDATE/DELETE/TRUNCATE, now or via a regression.
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON audit_events FROM risksignal_app;

-- Every table created later defaults to SELECT + INSERT for the application
-- role — no UPDATE/DELETE by default either (least privilege by construction).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT ON TABLES TO risksignal_app;

-- The migrator role owns schema changes: it may create and alter the schema.
GRANT USAGE, CREATE ON SCHEMA public TO risksignal_migrator;
GRANT ALL ON ALL TABLES IN SCHEMA public TO risksignal_migrator;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO risksignal_migrator;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON TABLES TO risksignal_migrator;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON SEQUENCES TO risksignal_migrator;

COMMENT ON ROLE risksignal_app IS
    'Application runtime group role (ARCH-007 §7 control 3a): INSERT/SELECT only on the append-only audit_events; grant it to the runtime login';
COMMENT ON ROLE risksignal_migrator IS
    'Migration group role (ARCH-007 §7 control 3a): owns schema changes; grant it to the migration login and run migrations as it';
