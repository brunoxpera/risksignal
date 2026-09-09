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
