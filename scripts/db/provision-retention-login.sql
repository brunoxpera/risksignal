-- RiskSignal — provision the dedicated retention login for local development
-- (DEV-129, ARCH-007 §7 control 3a amendment).
--
-- Migration 00015 creates the retention group role `risksignal_retention`, its
-- `risksignal_retention_login` LOGIN and the grant of the group to the login,
-- but carries no password (credentials are runtime-injected, concept ch. 3.3).
-- This snippet is that runtime injection for the local environment: it gives
-- the migration-created login a password so the compose `server`/`worker`
-- services can authenticate on the dedicated retention connection
-- (database.retention_url / RISKSIGNAL_DATABASE_RETENTION_URL) over the
-- compose network, where PostgreSQL asks for scram-sha-256.
--
-- Idempotent: it creates the login only if a database somehow lacks it, always
-- (re-)sets the password and LOGIN attribute, and (re-)asserts the grant the
-- migration made — a re-run converges to the same state. The group role and
-- its grant matrix stay migration 00015's responsibility; the grant below is
-- applied only once the group role exists, so run the snippet after
-- `make migrate` (the `make provision-retention-login` target depends on it).
--
-- Production operators run the same statements with a secret-managed password
-- (docs/operations/security-hardening.md, "Provisioning the retention login").
--
-- Invoked by `make provision-retention-login` as:
--   psql -v ON_ERROR_STOP=1 -v retention_password="$PW" -f <this file>

\set ON_ERROR_STOP on

-- The login: created by migration 00015; created here too so the snippet stays
-- self-contained if ever run against a database that predates the migration.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'risksignal_retention_login') THEN
        CREATE ROLE risksignal_retention_login LOGIN;
    END IF;
END
$$;

-- Runtime-injected password. `:'retention_password'` is psql's safe literal
-- quoting, so the value travels on the command line and never lands in the
-- file. LOGIN is restated so a login a database left NOLOGIN converges back to
-- a usable one.
ALTER ROLE risksignal_retention_login WITH LOGIN PASSWORD :'retention_password';

-- Grant the migration-created group role when it is present (post-migrate).
-- Migration 00015 already issued this grant; re-issuing it is a no-op.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'risksignal_retention') THEN
        GRANT risksignal_retention TO risksignal_retention_login;
    END IF;
END
$$;
