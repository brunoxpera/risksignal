-- sla_clocks: the per-signal SLA clock statements (ARCH-004 §4, WP-4.03 /
-- DEV-073).
--
-- One clock per (signal_id, target); UQ (signal_id, target) makes the write
-- a natural-key upsert and the reads single-row. deadline_at is frozen at
-- creation and the effective deadline is deadline_at + paused_seconds +
-- (now − paused_at while paused): pauses are not retroactive (ch. 9.4) and
-- the remaining time is frozen while paused. Fulfil is idempotent — a
-- fulfilled clock is never re-opened. The command layer (WP-4.04/4.05)
-- supplies the injected clock instants; this file only persists.

-- UpsertSlaClock writes one clock's full state by its natural key
-- (signal_id, target): a fresh insert, or the full-state replacement of the
-- existing clock (started_at/deadline_at/fulfil/pause counters). It is the
-- create path and the reopen reset in one statement — the caller passes the
-- reset state (started_at = now, deadline_at = now + duration, fulfilled_at
-- NULL, zeroed pause counters) to reopen a clock. RETURNING * hands the
-- stored row back.
-- name: UpsertSlaClock :one
INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at, fulfilled_at, paused_seconds, paused_at)
VALUES (@signal_id, @target, @started_at, @deadline_at, @fulfilled_at, @paused_seconds, @paused_at)
ON CONFLICT (signal_id, target) DO UPDATE SET
    started_at     = EXCLUDED.started_at,
    deadline_at    = EXCLUDED.deadline_at,
    fulfilled_at   = EXCLUDED.fulfilled_at,
    paused_seconds = EXCLUDED.paused_seconds,
    paused_at      = EXCLUDED.paused_at
RETURNING *;

-- GetSlaClock reads one clock by its natural key (signal_id, target) — the
-- read the priority-upgrade treatment takes before it decides whether a
-- target's clock is missing (create it) or present (tighten it if the new
-- deadline is earlier). It runs on the caller's transaction so the read sees
-- the same snapshot the following write acts on.
-- name: GetSlaClock :one
SELECT *
FROM sla_clocks
WHERE signal_id = @signal_id AND target = @target;

-- TightenSlaClock shortens the deadline of an open clock on a priority
-- upgrade (ARCH-004 §4.3): the deadline becomes the new value only when it
-- is earlier than the stored one, so an upgrade never lengthens a clock and
-- a re-run is idempotent. The fulfilled_at IS NULL guard leaves a fulfilled
-- clock untouched (its target is met; there is no window to shorten). A
-- clock that is missing, already fulfilled or already at least as early
-- matches zero rows — the adapter reports "not tightened".
-- name: TightenSlaClock :one
UPDATE sla_clocks SET
    deadline_at = @deadline_at
WHERE signal_id = @signal_id AND target = @target
  AND fulfilled_at IS NULL AND deadline_at > @deadline_at
RETURNING *;

-- FulfilSlaClock marks the target met at the instant (ARCH-004 §4.3). The
-- fulfilled_at IS NULL guard makes it idempotent: the first fulfil matches
-- the row, an already-fulfilled clock matches zero rows (the adapter reports
-- "already fulfilled") — a fulfilled clock is never re-opened.
-- name: FulfilSlaClock :one
UPDATE sla_clocks SET
    fulfilled_at = @fulfilled_at
WHERE signal_id = @signal_id AND target = @target AND fulfilled_at IS NULL
RETURNING *;

-- PauseSlaClock starts a pause at the instant (ARCH-004 §4.3): paused_at is
-- set while the clock runs (fulfilled_at IS NULL and not already paused). A
-- fulfilled or already-paused clock matches zero rows.
-- name: PauseSlaClock :one
UPDATE sla_clocks SET
    paused_at = @paused_at
WHERE signal_id = @signal_id AND target = @target
  AND fulfilled_at IS NULL AND paused_at IS NULL
RETURNING *;

-- ResumeSlaClock ends the active pause at the instant: the elapsed pause is
-- accumulated into paused_seconds (whole seconds) and paused_at is cleared.
-- Only a currently-paused clock matches. Pauses are not retroactive, so the
-- accumulation is added to, never folded into, the frozen deadline. The
-- elapsed seconds are the numeric difference of the two epochs cast once, so
-- the whole-second truncation happens after the subtraction (never a double
-- rounding).
-- name: ResumeSlaClock :one
UPDATE sla_clocks SET
    paused_seconds = paused_seconds + (EXTRACT(EPOCH FROM @resumed_at::timestamptz) - EXTRACT(EPOCH FROM paused_at))::bigint,
    paused_at      = NULL
WHERE signal_id = @signal_id AND target = @target AND paused_at IS NOT NULL
RETURNING *;

-- ResetSlaClock restarts one clock on a reopen (ARCH-004 §4.3): started_at
-- = now, deadline_at = now + duration, fulfilled_at cleared and the pause
-- counters zeroed. The prior clock history lives in the audit, not the row.
-- The caller resets only the targets defined at the current priority; this
-- statement resets one (signal_id, target) clock.
-- name: ResetSlaClock :one
UPDATE sla_clocks SET
    started_at     = @started_at,
    deadline_at    = @deadline_at,
    fulfilled_at   = NULL,
    paused_seconds = 0,
    paused_at      = NULL
WHERE signal_id = @signal_id AND target = @target
RETURNING *;

-- ScanDueSlaClocks is the sla.evaluate breach scan (ARCH-004 §4.3/§4.4): the
-- open clocks (fulfilled_at IS NULL) whose effective deadline has passed.
-- The effective deadline is deadline_at + paused_seconds + (now − paused_at
-- while paused) — the paused_seconds term unfreezes the frozen deadline by
-- the accumulated pauses, and the COALESCE term adds the currently running
-- pause; both are zero/interval '0' for a never-paused clock, so a running
-- clock compares deadline_at <= now directly. Ordered by deadline_at (the
-- IX sla_clocks_deadline_at index drives the scan), then signal_id/target for
-- a deterministic order. The caller (worker) decides escalation per priority.
-- name: ScanDueSlaClocks :many
SELECT *
FROM sla_clocks
WHERE fulfilled_at IS NULL
  AND (
      deadline_at
      + make_interval(secs => paused_seconds::double precision)
      + COALESCE(now() - paused_at, interval '0')
  ) <= now()
ORDER BY deadline_at, signal_id, target;
