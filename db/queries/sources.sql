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

-- SetSourceLastContentHash records the content hash of the source's last
-- committed raw record into sources.config.last_content_hash (DEV-041,
-- ARCH-002 §1/§2.2/§2.3, ch. 8.3). The fetch use cases run the update in
-- the same transaction as the raw-record insert and the run completion, so
-- the stored hash advances only with a committed run (ch. 6.1). The next
-- fetch of a full-set source (KEV, EPSS) compares the fetched document's
-- hash against the stored one and reports FetchMeta.NoChange on a match —
-- the successful no-op of an unchanged catalog/daily file (the fetch use
-- case hands the hash to the adapter through the descriptor it resolves;
-- the adapter never reads the database). The jsonb merge keeps every other
-- config member (window, overlap, api_key_ref — the secret reference,
-- never a literal) intact and is NULL-safe (COALESCE) for sources whose
-- config has never been set.
-- name: SetSourceLastContentHash :exec
UPDATE sources
SET config = COALESCE(config, '{}'::jsonb) || jsonb_build_object('last_content_hash', @content_hash::text)
WHERE id = @id;

-- SetSourceCursor promotes the watermark of one successful run back into
-- sources.cursor (DEV-067, ARCH-003 §6): the fetch use cases (FetchSource,
-- RunSource) run the update in the same transaction as the raw-record
-- insert and the run completion, so the source cursor advances only with a
-- committed successful run (ch. 6.1 — a failed run leaves the cursor
-- untouched and the next fetch re-runs the same window). The I2 code
-- persisted cursor_before/cursor_after on source_runs but never promoted
-- the row cursor; without the promotion every fetch re-read the original
-- cursor, and the checkpointed windows of the full import could never
-- advance. Cursor-less (full-set) sources never call it — their fetches
-- carry no cursor value to promote.
-- name: SetSourceCursor :exec
UPDATE sources
SET cursor = @cursor
WHERE id = @id;

-- ListEnabledScheduledSources returns the rows the scheduler scan checks
-- (WP-2.08/DEV-042, ARCH-002 §5): every enabled source whose schedule is
-- set — NULL schedules (e.g. the operator-triggered synthetic source) never
-- appear. The scan derives each row's due schedule slot from the schedule
-- string and enqueues the source.fetch job of the slot; id and type carry
-- the row identity, schedule the slot grammar ("@hourly", "@daily" — the
-- schedules the I2 adapters declare).
-- name: ListEnabledScheduledSources :many
SELECT id, type, schedule
FROM sources
WHERE enabled = true AND schedule IS NOT NULL
ORDER BY id;

-- ListSourcesByType returns every source row of one type — the read the
-- `source run <type>` resolution of the CLI performs (WP-2.08/DEV-042,
-- ARCH-002 §5): a type names its source row when exactly one is
-- registered, and the resolution fails on zero or several. name is carried
-- so the error can name the ambiguous rows.
-- name: ListSourcesByType :many
SELECT id, type, name
FROM sources
WHERE type = @type
ORDER BY name, id;

-- ListSources returns every source row the source monitor projects over
-- (WP-2.08b/DEV-043, ARCH-002 §5): the monitor joins this base read with
-- the latest source_runs rows and the open quarantine counts. schedule is
-- carried so the monitor derives the source's planned interval (the stale
-- threshold of ch. 16.3/16.4 — data age > 2 planned intervals is surfaced
-- as degraded); endpoint is the public base URL of the source, never a
-- secret (config, which holds the api_key_ref secret reference, is not
-- selected). Rows are ordered by type, then name, then id — a stable
-- operator-facing order.
-- name: ListSources :many
SELECT id, type, name, endpoint, schedule, enabled
FROM sources
ORDER BY type, name, id;
