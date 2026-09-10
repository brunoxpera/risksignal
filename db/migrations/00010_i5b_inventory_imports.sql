-- 00010_i5b_inventory_imports.sql — I5b inventory-import staging table
-- (ARCH-006 §2.1/§7, WP-5b.02 / DEV-098).
--
-- Iteration I5b exposes the deferred I3 inventory import as a *staged*
-- HTTP flow (upload → preview → commit, ARCH-006 §2.1): POST /inventory/
-- imports stores the uploaded CSV bytes and the validation/preview report,
-- GET /inventory/imports/{id} reads it back, and POST /inventory/imports/
-- {id}/commit loads the stored bytes and runs the existing I3 branch
-- command CommitInventory over them. The I3 command works on in-memory
-- File []byte and generates its own fresh audit ImportID, so there is
-- nothing to GET by id today; this table is that missing persistence
-- record. It is persistence, not business logic: the staged commit reuses
-- the I3 parser/upsert/audit/job code verbatim (ARCH-006 §2.1).
--
-- The table is purely additive (ADR-010): no existing table, column or
-- constraint changes meaning, and no existing row is touched. It is
-- deliberately *small* — the uploaded bytes (bounded by the application's
-- InventoryMaxBytes), the lifecycle status, the preview tallies and the
-- attribution. The tallies are the staging-side counters of the upload's
-- validation/preview (rows read, positioned problems, data-quality
-- warnings) plus the four commit-outcome counters (assets/components
-- created/updated) the commit arm stamps when it marks the record
-- committed; they are denormalised onto the record so GET can return the
-- stored report without re-parsing the file.
--
-- The commit arm is idempotent (ARCH-006 §2.1: "Re-commit is a no-op"):
-- MarkInventoryImportCommitted is guarded `WHERE status = 'pending'`, so a
-- second commit of an already-committed record matches zero rows and
-- returns nothing — the caller returns the stored result without re-running
-- the (transactional, audited) I3 command. status is a fixed three-value
-- vocabulary (pending | committed | failed) enforced as a DB CHECK, the
-- same controlled-vocabulary style as user_roles.role (00009).
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- inventory_imports (ARCH-006 §2.1/§7): one staged inventory upload. id is
-- the opaque import id the API returns and the Get/Commit endpoints resolve
-- (gen_random_uuid() — not the I3 command's audit ImportID, which the commit
-- arm generates internally). status tracks the staged lifecycle; file holds
-- the uploaded CSV bytes verbatim (the same bytes ValidateCSVInventory and
-- CommitInventory consume, capped at InventoryMaxBytes by the HTTP body
-- limit before the insert). rows/error_count/warning_count are the upload's
-- validation/preview counters; assets_created/assets_updated/
-- components_created/components_updated are the commit-outcome counters the
-- commit arm stamps. actor_id is the authenticated principal that staged the
-- upload (users.id for a user actor, the channel's dev subject otherwise —
-- the same value the I3 commit's audit actor stores); correlation_id links
-- the record to the command's audit/outbox correlation id and is nullable
-- (a staged upload that carries no correlation). created_at is the staging
-- instant from the injected clock; committed_at is the commit instant (NULL
-- while pending or failed).
CREATE TABLE inventory_imports (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    status             text        NOT NULL,
    file               bytea       NOT NULL,
    rows               int         NOT NULL DEFAULT 0,
    error_count        int         NOT NULL DEFAULT 0,
    warning_count      int         NOT NULL DEFAULT 0,
    assets_created     int         NOT NULL DEFAULT 0,
    assets_updated     int         NOT NULL DEFAULT 0,
    components_created int         NOT NULL DEFAULT 0,
    components_updated int         NOT NULL DEFAULT 0,
    actor_id           text        NOT NULL,
    correlation_id     text        NULL,
    created_at         timestamptz NOT NULL,
    committed_at       timestamptz NULL,
    CONSTRAINT inventory_imports_status_check CHECK (status IN ('pending', 'committed', 'failed'))
);

-- IX (status, created_at) serves the lifecycle reads: the pending-import
-- scan (the records a commit/cancel pass over) and the operator list ordered
-- by staging instant. It is the only secondary read; the by-id Get/Commit
-- resolves through the primary key.
CREATE INDEX inventory_imports_status_created_at_idx ON inventory_imports (status, created_at);

COMMENT ON TABLE inventory_imports IS
    'Staged inventory-import records (ARCH-006 §2.1, WP-5b.02): uploaded CSV bytes + validation/preview report + commit outcome, keyed by the opaque import id the API returns; the staged commit runs the existing I3 CommitInventory over the stored bytes and marks the record committed';
COMMENT ON COLUMN inventory_imports.id IS
    'Opaque import id returned by POST /inventory/imports and resolved by the Get/Commit endpoints (gen_random_uuid()); distinct from the I3 command''s internal audit ImportID';
COMMENT ON COLUMN inventory_imports.status IS
    'Staged lifecycle: pending | committed | failed (inventory_imports_status_check) — the commit guard flips pending → committed exactly once';
COMMENT ON COLUMN inventory_imports.file IS
    'Uploaded CSV bytes verbatim — the same bytes ValidateCSVInventory and CommitInventory consume; bounded by the application InventoryMaxBytes (16 MiB) at the HTTP body limit';
COMMENT ON COLUMN inventory_imports.rows IS
    'Data rows the upload''s CSV reader delimited (the upload report counter)';
COMMENT ON COLUMN inventory_imports.error_count IS
    'Positioned validation problems of the upload (the upload report counter)';
COMMENT ON COLUMN inventory_imports.warning_count IS
    'Data-quality warnings of the upload (unknown criticality/exposure — the upload report counter)';
COMMENT ON COLUMN inventory_imports.assets_created IS
    'Inventory assets the commit created (commit-outcome counter, stamped when the record is marked committed)';
COMMENT ON COLUMN inventory_imports.assets_updated IS
    'Inventory assets the commit refreshed (commit-outcome counter)';
COMMENT ON COLUMN inventory_imports.components_created IS
    'Inventory components the commit created (commit-outcome counter)';
COMMENT ON COLUMN inventory_imports.components_updated IS
    'Inventory components the commit refreshed (commit-outcome counter)';
COMMENT ON COLUMN inventory_imports.actor_id IS
    'Authenticated principal that staged the upload (users.id for a user actor, the channel dev subject otherwise) — the same value the I3 commit''s audit actor stores';
COMMENT ON COLUMN inventory_imports.correlation_id IS
    'Correlation id linking the record to the staging command''s audit/outbox rows; NULL when the staging carried none';
COMMENT ON COLUMN inventory_imports.created_at IS
    'Staging instant from the injected clock';
COMMENT ON COLUMN inventory_imports.committed_at IS
    'Commit instant from the injected clock; NULL while the record is pending or failed';
COMMENT ON CONSTRAINT inventory_imports_status_check ON inventory_imports IS
    'The fixed staged lifecycle vocabulary (ARCH-006 §2.1): pending | committed | failed';
