-- 00001_schema_migration_log.sql — own migration checksum log (ADR-010, WP-1a.04).
--
-- ADR-010 requires that every applied migration is recorded with the version,
-- a hash of the migration file content, a timestamp and the duration. That is
-- our own table, separate from goose's bookkeeping (goose_db_version), and it
-- is created by the first migration so it exists before any later migration
-- can be applied.
--
-- duration_ms is NULL for rows that were recovered after a crash (the log
-- insert could not keep up with goose's commit) — for those the original
-- duration is not known. Freshly applied migrations always carry it.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up
CREATE TABLE schema_migration_log (
    version     BIGINT      NOT NULL,
    file_hash   TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms BIGINT,
    CONSTRAINT schema_migration_log_version_key UNIQUE (version)
);

COMMENT ON TABLE schema_migration_log IS
    'Checksum log of applied migrations (ADR-010): one row per applied migration, keyed by goose version';
COMMENT ON COLUMN schema_migration_log.file_hash IS
    'SHA-256 of the applied migration file content (hex); verified against the embedded file before every run';
COMMENT ON COLUMN schema_migration_log.duration_ms IS
    'Duration of the migration run; NULL when the row was recovered after a crash';
