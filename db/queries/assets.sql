-- assets: inventory asset seed write and lifecycle statements (ARCH-001 §1,
-- WP-1b.05 demo seed; ARCH-003 §1.1 lifecycle, WP-3.03a / DEV-056).
-- Deactivation is explicit and never implicit (an import that stops
-- carrying a row never deactivates it — ARCH-003 §1.3); the lifecycle
-- writes below are the operator transitions, both stamping updated_at from
-- the injected clock so any inventory mutation bumps the inventory_snapshot
-- hash of matching.rebuild (ARCH-003 §5).

-- UpsertAsset inserts or refreshes an inventory asset by its natural key
-- (source, external_id) and returns its id: the demo seed must be
-- idempotent, so seeding twice yields no duplicates. created_at stays the
-- original registration time; the refresheable fields follow the seed data.
-- name: UpsertAsset :one
INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure, owner)
VALUES (@external_id, @source, @type, @name, @environment, @criticality, @exposure, @owner)
ON CONFLICT (source, external_id) DO UPDATE SET
    type        = EXCLUDED.type,
    name        = EXCLUDED.name,
    environment = EXCLUDED.environment,
    criticality = EXCLUDED.criticality,
    exposure    = EXCLUDED.exposure,
    owner       = EXCLUDED.owner
RETURNING id;

-- ImportUpsertAsset inserts or refreshes an inventory asset by its
-- natural key (source, external_id) from an inventory import commit
-- (ARCH-003 §1.1/§1.3, WP-3.05b / DEV-060). It is the UpsertAsset shape
-- with the clock-stamped updated_at supplied explicitly: ARCH-003 §1.1
-- pins "updated_at is stamped by the injected clock on upsert and drives
-- the inventory_snapshot hash (§5)" — the import commit writes its stamp
-- on insert AND on conflict refresh (the demo-seed UpsertAsset keeps the
-- DB default backstop and refreshes no timestamp, the pre-I3 path). The
-- refresh never touches created_at, deactivated_at or verified_at —
-- deactivation is explicit lifecycle, never an import side effect
-- (ARCH-003 §1.3 additive upsert: absence never deactivates), and a
-- deactivated asset that reappears in an import stays deactivated.
-- name: ImportUpsertAsset :one
INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure, owner, updated_at)
VALUES (@external_id, @source, @type, @name, @environment, @criticality, @exposure, @owner, @updated_at)
ON CONFLICT (source, external_id) DO UPDATE SET
    type        = EXCLUDED.type,
    name        = EXCLUDED.name,
    environment = EXCLUDED.environment,
    criticality = EXCLUDED.criticality,
    exposure    = EXCLUDED.exposure,
    owner       = EXCLUDED.owner,
    updated_at  = EXCLUDED.updated_at
RETURNING id;

-- GetAssetBySourceExternalID resolves one asset by its import natural key
-- (source, external_id, UQ (source, external_id) — ARCH-003 §1.1): the
-- current-state read of the WP-3.05 import preview/commit (DEV-059/060,
-- application.InventoryRepo.CurrentAsset). A missing row is pgx.ErrNoRows
-- — the normal "created" outcome of the preview, not an error. The row
-- carries the full lifecycle state (updated_at drives the
-- inventory_snapshot hash; deactivated_at/verified_at are rendered as-is,
-- never interpreted here).
-- name: GetAssetBySourceExternalID :one
SELECT id, external_id, source, type, name, environment, criticality, exposure, owner,
       created_at, updated_at, deactivated_at, verified_at
FROM assets
WHERE source = @source AND external_id = @external_id;

-- DeactivateAsset soft-deactivates one asset (ARCH-003 §1.1: "soft-
-- deactivate, never delete — deactivated assets stay historically
-- referenceable", ch. 6.1): deactivated_at and updated_at come from the
-- injected clock. The WHERE guard makes the transition idempotent at the
-- statement level — an already-deactivated asset is left untouched and the
-- returned row count is 0, so the caller can surface the guarded domain
-- transition (domain.Asset.Deactivate errors on a repeated deactivation)
-- without racing a concurrent writer.
-- name: DeactivateAsset :execrows
UPDATE assets
SET deactivated_at = @deactivated_at,
    updated_at     = @updated_at
WHERE id = @id
  AND deactivated_at IS NULL;

-- VerifyAsset records a manual data-quality verification (ARCH-003 §1.1
-- verified_at: "last manual data-quality verification", ch. 11.1):
-- verified_at and updated_at come from the injected clock. Verification is
-- repeatable — every operator check re-verifies the row — and independent
-- of the deactivation state (domain.Asset.Verify), so the statement has no
-- state guard; the returned row count is 0 only for an unknown id.
-- name: VerifyAsset :execrows
UPDATE assets
SET verified_at = @verified_at,
    updated_at  = @updated_at
WHERE id = @id;
