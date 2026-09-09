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
