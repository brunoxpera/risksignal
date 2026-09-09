-- source_runs lifecycle writes (ARCH-001 §1, WP-1b.02).
--
-- Exactly one end state per run; counters advance only on success
-- (concept ch. 6.1 SourceRun, ARCH-001 §3 step 1 and 6).

-- CreateSourceRun opens a run with status 'running' and the default empty
-- counters. started_at comes from the injected clock (ch. 7.2) — never the
-- database clock — so runs are reproducible in tests.
-- name: CreateSourceRun :one
INSERT INTO source_runs (source_id, started_at, status)
VALUES (@source_id, @started_at, 'running')
RETURNING *;

-- CompleteSourceRun closes a run with its terminal state: status succeeded
-- or failed, finished_at, the committed counters and the error text of a
-- failed run (concept ch. 8.1 step 5: the E1 error is counted and recorded,
-- it does not abort the other cases).
-- name: CompleteSourceRun :one
UPDATE source_runs
SET finished_at = @finished_at,
    status      = @status,
    counters    = @counters,
    error       = @error
WHERE id = @id
RETURNING *;
