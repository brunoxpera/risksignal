-- source_runs lifecycle writes (ARCH-001 §1, WP-1b.02; cursor bookkeeping
-- ARCH-002 §1/§3, WP-2.03b).
--
-- Exactly one end state per run; counters advance only on success
-- (concept ch. 6.1 SourceRun, ARCH-001 §3 step 1 and 6). From migration
-- 00004 on a run also carries the I2 cursor bookkeeping (ch. 7.1):
-- cursor_before is the cursor value when the run opened, cursor_after the
-- cursor committed with a successful run. The cursor advances only after
-- commit — cursor_after is written exclusively by the success path of
-- CompleteSourceRun and stays NULL on a failed run, so a failure leaves the
-- source cursor where it was and the next run re-fetches the same window
-- (ARCH-002 §1/§2.1, ch. 8.2). Full-set sources (KEV, EPSS) and the I1b
-- synthetic source have no cursor and leave both fields NULL.

-- CreateSourceRun opens a run with status 'running' and the default empty
-- counters. started_at comes from the injected clock (ch. 7.2) — never the
-- database clock — so runs are reproducible in tests. cursor_before records
-- the source cursor value the run opened from (the value the fetch half
-- read off sources.cursor before fetching); NULL for full-set sources and
-- the cursor-less I1b synthetic source.
-- name: CreateSourceRun :one
INSERT INTO source_runs (source_id, started_at, status, cursor_before)
VALUES (@source_id, @started_at, 'running', @cursor_before)
RETURNING *;

-- CompleteSourceRun closes a run with its terminal state: status succeeded
-- or failed, finished_at, the committed counters and the error text of a
-- failed run (concept ch. 8.1 step 5: the E1 error is counted and recorded,
-- it does not abort the other cases).
--
-- cursor_after is the cursor committed with a successful run only (ch. 6.1,
-- ARCH-002 §1): the CASE guard writes the caller's cursor_after when the
-- terminal status is 'succeeded' and NULL otherwise, so a failed run can
-- never advance the cursor — the next run starts again from cursor_before.
-- The caller passes the cursor value of a succeeded run and NULL (or the
-- same value, which is ignored) of a failed one. The ::jsonb cast pins the
-- parameter's type — inside a CASE the planner would otherwise infer text
-- for the untyped parameter and the jsonb assignment would fail.
-- name: CompleteSourceRun :one
UPDATE source_runs
SET finished_at  = @finished_at,
    status       = @status,
    counters     = @counters,
    error        = @error,
    cursor_after = CASE WHEN @status = 'succeeded' THEN @cursor_after::jsonb ELSE NULL END
WHERE id = @id
RETURNING *;

-- GetSourceRunByID loads one run with its cursor fields — the read the
-- source monitor and any caller that needs the committed cursor_after /
-- opened cursor_before of a run starts from.
-- name: GetSourceRunByID :one
SELECT *
FROM source_runs
WHERE id = @id;

-- LatestSourceRunBySource returns the latest run of every source that has
-- run at all (WP-2.08b/DEV-043, ARCH-002 §5): the monitor read of the
-- per-source last run (status, finished_at, counters, error, cursor). The
-- DISTINCT ON picks the newest row per source_id by started_at (id is the
-- deterministic tiebreak for the same clock instant); the row's own index
-- (source_id, started_at DESC) serves the scan. The latest run may still
-- be 'running' — an in-flight run the monitor reports as such while the
-- data age falls back to the latest successful run (which is read
-- separately, LatestSucceededSourceRunBySource).
-- name: LatestSourceRunBySource :many
SELECT DISTINCT ON (source_id)
    source_id, id, status, started_at, finished_at, counters, error, cursor_after
FROM source_runs
ORDER BY source_id, started_at DESC, id DESC;

-- LatestSucceededSourceRunBySource returns the latest successful run of
-- every source that has one (WP-2.08b/DEV-043, ARCH-002 §5): the monitor's
-- data-age read. Data age is clock.Now() − the last successful run's
-- finished_at (ARCH-002 §5), and for an incremental source the committed
-- cursor_after (the NVD last_modified member) is the data-freshness basis
-- the monitor prefers over finished_at. Sources without a successful run
-- have no row here — the monitor reports them as never-succeeded (no data
-- age, never degraded on the age criterion).
-- name: LatestSucceededSourceRunBySource :many
SELECT DISTINCT ON (source_id)
    source_id, id, status, started_at, finished_at, counters, error, cursor_after
FROM source_runs
WHERE status = 'succeeded'
ORDER BY source_id, started_at DESC, id DESC;
