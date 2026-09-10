-- exports: the asynchronous CSV/JSON export job statements (ARCH-007 §1.2,
-- WP-6.02 / DEV-112).
--
-- An export is a materialised background job, not an on-demand query: the
-- CreateExport use case freezes the §10.4 filter context plus the creation
-- instant and inserts a 'pending' row, and the export.generate worker job
-- materialises the artifact, stamps the generation columns and flips the row
-- to 'completed' (or 'failed'). The artifact itself is a file in the
-- server-local spool — only its reference (storage_path/size_bytes/checksum)
-- and the generation stamps live here. The expiry sweep reads the completed
-- rows past their TTL and marks them 'expired'. No statement here touches
-- another table: the export is a read-materialisation of the existing signal
-- set (the SignalExportSource read in export_source.sql).

-- InsertExport creates one export in status 'pending' and returns the stored
-- row with its database-assigned id. The caller passes the frozen filter
-- context (jsonb), the format and the creator; created_at comes from the
-- injected clock. The generation columns keep their column defaults (NULL)
-- until the export.generate job stamps them.
-- name: InsertExport :one
INSERT INTO exports (
    status, filter, format, created_by, created_at
)
VALUES (
    'pending', @filter, @format, @created_by, @created_at
)
RETURNING *;

-- GetExport reads one export by its id — the GET /exports/{id} status read
-- and the load step of the export.generate job (it reads the frozen filter
-- and status before materialising) and of the download (it checks the expiry
-- and the storage reference). A missing id is pgx.ErrNoRows, mapped to a
-- not-found error.
-- name: GetExport :one
SELECT *
FROM exports
WHERE id = @id;

-- MarkExportCompleted stamps the generation outcome and flips the export to
-- 'completed' in one statement: the spool reference, the materialised row
-- count and size, the artifact SHA-256 and the schema/rule versions stamped
-- at generation time, the expiry (created_at + export.ttl) and the cleared
-- error. The `status IN ('pending','failed')` guard makes a retry idempotent
-- at the statement level (ARCH-007 §1.2: a crashed/failed generation is
-- regenerated and re-stamps the row) while an already-completed or expired
-- row matches zero rows (pgx.ErrNoRows) — nothing is re-stamped.
-- name: MarkExportCompleted :one
UPDATE exports
SET status         = 'completed',
    storage_path   = @storage_path,
    row_count      = @row_count,
    size_bytes     = @size_bytes,
    checksum       = @checksum,
    schema_version = @schema_version,
    rule_version   = @rule_version,
    expires_at     = @expires_at,
    last_error     = NULL
WHERE id = @id
  AND status IN ('pending', 'failed')
RETURNING *;

-- MarkExportFailed records a failed generation: status 'failed' + last_error,
-- visible like any dead-letter/source-runs error (ARCH-007 §1.2). The
-- `status IN ('pending','failed')` guard lets a retried failing generation
-- re-stamp the error but never overwrites a completed or expired row (zero
-- rows → pgx.ErrNoRows).
-- name: MarkExportFailed :one
UPDATE exports
SET status     = 'failed',
    last_error = @last_error
WHERE id = @id
  AND status IN ('pending', 'failed')
RETURNING *;

-- ListExpiredExports returns the completed exports whose TTL elapsed
-- (expires_at <= @now) ordered by expiry then id — the input of the daily
-- export sweep (ARCH-007 §1.2: the sweep deletes the expired artifacts and
-- marks the rows 'expired'). A completed row always carries expires_at
-- (stamped with the generation), so the NOT NULL guard simply keeps pending/
-- failed rows (NULL expiry) out of the sweep. No expired export yields no
-- rows, never an error.
-- name: ListExpiredExports :many
SELECT *
FROM exports
WHERE status = 'completed'
  AND expires_at IS NOT NULL
  AND expires_at <= @now
ORDER BY expires_at, id;

-- MarkExportExpired flips a completed export to 'expired' after the sweep
-- deleted its artifact. The `status = 'completed'` guard makes the mark
-- idempotent (a second sweep of the same row matches zero rows) and never
-- re-expires a pending/failed row.
-- name: MarkExportExpired :one
UPDATE exports
SET status = 'expired'
WHERE id = @id
  AND status = 'completed'
RETURNING *;
