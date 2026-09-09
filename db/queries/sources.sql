-- Source queries: seed write + the run-path read (ARCH-001 §1, WP-1b.02).
--
-- The I1b synthetic source is a real, configured source row (ch. 8.5); the
-- demo seed registers it (WP-1b.05) and `demo run` loads it by natural key.

-- UpsertSource registers a source by its natural key (type, name) and
-- returns its id. The seed path must be idempotent — seeding twice yields no
-- duplicates — so a conflict refreshes `enabled` only; the reserved columns
-- (endpoint, schedule, cursor, config) keep what they hold.
-- name: UpsertSource :one
INSERT INTO sources (type, name, endpoint, schedule, enabled, cursor, config)
VALUES (@type, @name, @endpoint, @schedule, @enabled, @cursor, @config)
ON CONFLICT (type, name) DO UPDATE SET
    enabled = EXCLUDED.enabled
RETURNING id;

-- GetSourceByTypeAndName loads one source by its natural key — e.g. the
-- synthetic source (type = 'synthetic') that `demo run` executes.
-- name: GetSourceByTypeAndName :one
SELECT id, type, name, endpoint, schedule, enabled, cursor, config, created_at
FROM sources
WHERE type = @type AND name = @name;

-- GetSourceByID loads one source row by id — the descriptor read the I2
-- run use cases (FetchSource / RunSource / quarantine reprocess, ARCH-002
-- §1) resolve a run's or raw record's source from (the scheduler and the
-- source registry read the same row; runs, raw records and quarantine rows
-- all attribute by sources.id).
-- name: GetSourceByID :one
SELECT id, type, name, endpoint, schedule, enabled, cursor, config, created_at
FROM sources
WHERE id = @id;
