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

-- ListAssets is the inventory working-list read (ARCH-006 §2.2 ListAssets,
-- GET /assets): every visible column of the assets table, ordered by
-- created_at then id (a stable sort — id is the tiebreak, so equal stamps
-- still paginate deterministically). type/environment/criticality/exposure/
-- owner_id/source filter optionally — pass NULL to keep a filter open. The
-- owner_id filter is the object-scope injection point of an `assigned`/`own`
-- read grant (ARCH-005 §5, ARCH-006 §2.2): a Systemverantwortliche sees only
-- their owned assets (a.owner = owner_id). The read is paginated by the
-- caller-supplied window (max_rows = offset+limit+1), like ListSignals.
-- name: ListAssets :many
SELECT
    a.id,
    a.external_id,
    a.source,
    a.type,
    a.name,
    a.environment,
    a.criticality,
    a.exposure,
    a.owner,
    a.created_at,
    a.updated_at,
    a.deactivated_at,
    a.verified_at
FROM assets a
WHERE (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('environment')::text IS NULL OR a.environment = sqlc.narg('environment'))
  AND (sqlc.narg('criticality')::text IS NULL OR a.criticality = sqlc.narg('criticality'))
  AND (sqlc.narg('exposure')::text IS NULL OR a.exposure = sqlc.narg('exposure'))
  AND (sqlc.narg('owner_id')::text IS NULL OR a.owner = sqlc.narg('owner_id'))
  AND (sqlc.narg('source')::text IS NULL OR a.source = sqlc.narg('source'))
ORDER BY a.created_at, a.id
LIMIT @max_rows;

-- GetAssetComponents returns one asset together with its components
-- (ARCH-006 §2.2 GetAssetComponents, GET /assets/{id}/components). It is a
-- LEFT JOIN from the asset to its components (IX components_asset_id_idx),
-- so an asset with no components still returns one row — with NULL component
-- columns — instead of vanishing, and an unknown asset id returns no rows
-- (the adapter maps that to a not-found error). Components are ordered by
-- natural_key (the import idempotency key) so the read is stable, exactly
-- like ListComponentsByAsset; the component columns travel in their full I3
-- shape. The asset columns are NOT NULL (the WHERE pins the left row).
-- name: GetAssetComponents :many
SELECT
    a.id,
    a.external_id,
    a.source,
    a.type,
    a.name,
    a.environment,
    a.criticality,
    a.exposure,
    a.owner,
    a.created_at,
    a.updated_at,
    a.deactivated_at,
    a.verified_at,
    c.id             AS component_id,
    c.vendor         AS component_vendor,
    c.product        AS component_product,
    c.version        AS component_version,
    c.cpe            AS component_cpe,
    c.purl           AS component_purl,
    c.image          AS component_image,
    c.digest         AS component_digest,
    c.vendor_norm    AS component_vendor_norm,
    c.product_norm   AS component_product_norm,
    c.version_norm   AS component_version_norm,
    c.version_scheme AS component_version_scheme,
    c.natural_key    AS component_natural_key
FROM assets a
LEFT JOIN components c ON c.asset_id = a.id
WHERE a.id = @id
ORDER BY c.natural_key;
