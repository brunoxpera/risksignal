-- inventory_imports: the staged inventory-import persistence (ARCH-006 §2.1,
-- WP-5b.02 / DEV-098). The I5b HTTP/CLI staged flow uploads a CSV, persists
-- the record with its validation/preview report, and commits it by running
-- the existing I3 CommitInventory over the stored bytes. These four
-- statements are the whole staging surface: the insert, the by-id read, the
-- guarded commit-mark and the operator list. The commit arm's actual work —
-- parse, upsert, audit, enqueue matching.rebuild — is the I3 command; this
-- file never re-implements it.

-- InsertInventoryImport stores one staged upload in status 'pending' and
-- returns the stored record with its database-assigned id. status/file/
-- rows/error_count/warning_count/actor_id/created_at are required; the four
-- commit-outcome counters (assets_/components_created/updated) and
-- committed_at keep their column defaults (0 / NULL) until the commit arm
-- stamps them. correlation_id may be "" (NULL — the staging carried none).
-- name: InsertInventoryImport :one
INSERT INTO inventory_imports (
    status, file, rows, error_count, warning_count,
    actor_id, correlation_id, created_at
)
VALUES (
    @status, @file, @rows, @error_count, @warning_count,
    @actor_id, @correlation_id, @created_at
)
RETURNING *;

-- GetInventoryImport reads one staged record by its opaque import id — the
-- GET /inventory/imports/{id} read and the load step of the commit arm (it
-- reads the stored status before deciding between the no-op and the I3
-- command). A missing id is pgx.ErrNoRows, mapped to a not-found error.
-- name: GetInventoryImport :one
SELECT *
FROM inventory_imports
WHERE id = @id;

-- MarkInventoryImportCommitted flips a staged record to 'committed', stamps
-- committed_at from the injected clock and — atomically with the mark, in one
-- statement — populates the four commit-outcome counters (assets_/components_
-- created/updated) from the I3 CommitInventoryResult (ARCH-006 §2.1; DEV-098
-- review follow-up, wired by the WP-5b.03 commit arm). The `status = 'pending'`
-- guard makes the mark idempotent at the statement level: a second commit of an
-- already-committed (or failed) record matches zero rows and returns nothing
-- (pgx.ErrNoRows), so the caller returns the stored result without re-running
-- the command (ARCH-006 §2.1: re-commit is a no-op).
-- name: MarkInventoryImportCommitted :one
UPDATE inventory_imports
SET status             = 'committed',
    committed_at       = @now,
    assets_created     = @assets_created,
    assets_updated     = @assets_updated,
    components_created = @components_created,
    components_updated = @components_updated
WHERE id = @id
  AND status = 'pending'
RETURNING *;

-- ListInventoryImports returns every staged record ordered by staging
-- instant then id (oldest first, a stable order) — the operator list the
-- CLI/web inventory screens render. An empty table yields no rows, never an
-- error.
-- name: ListInventoryImports :many
SELECT *
FROM inventory_imports
ORDER BY created_at, id;
