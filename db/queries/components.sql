-- components: the inventory component statements (ARCH-003 §1.2/§1.3/§4,
-- WP-3.03a / DEV-056). The I1b 4-column seed write becomes the I3
-- natural-key upsert: every write through this file supplies the identifier
-- originals, the normalised comparison keys, the inferred version scheme
-- and the deterministic import idempotency key. The columns stay nullable
-- through the Expand phase of migration 00005 — SET NOT NULL and the
-- identifier CHECK are the Contract phase of 00006 (DEV-057) — but the I3
-- write path never leaves them NULL, so legacy rows written before this
-- switch stay distinguishable (NULL keys, no UQ participation) and are
-- backfilled/rewritten by the next import of their identity.

-- InsertComponent upserts one component row of an asset by its import
-- idempotency key UQ (asset_id, natural_key) (ARCH-003 §1.2/§1.3) and
-- returns the canonical row id — the freshly inserted one, or the already
-- existing one when the same asset carries the same natural key. Raw
-- originals (cpe/purl/image/digest) are preserved verbatim; the caller
-- supplies the normalised comparison keys (vendor_norm/product_norm/
-- version_norm: NFKC + trim + lowercase at write time, no alias — aliases
-- resolve at match time, ARCH-003 §2), the inferred version_scheme and the
-- natural key (the deterministic SHA-256 of the strongest identifier,
-- internal/domain/naturalkey.go). The conflict update refreshes the row and
-- stamps updated_at from the injected clock, keeps created_at at the
-- original registration time and never touches deactivated_at —
-- deactivation is explicit lifecycle, never an import side effect
-- (ARCH-003 §1.3: repeated imports upsert, never deactivate or reactivate).
-- A legacy row whose natural_key is NULL never conflicts and is left
-- untouched.
-- name: InsertComponent :one
INSERT INTO components (
    asset_id, vendor, product, version,
    cpe, purl, image, digest,
    vendor_norm, product_norm, version_norm, version_scheme,
    natural_key, updated_at
)
VALUES (
    @asset_id, @vendor, @product, @version,
    @cpe, @purl, @image, @digest,
    @vendor_norm, @product_norm, @version_norm, @version_scheme,
    @natural_key, @updated_at
)
ON CONFLICT (asset_id, natural_key) DO UPDATE SET
    vendor         = EXCLUDED.vendor,
    product        = EXCLUDED.product,
    version        = EXCLUDED.version,
    cpe            = EXCLUDED.cpe,
    purl           = EXCLUDED.purl,
    image          = EXCLUDED.image,
    digest         = EXCLUDED.digest,
    vendor_norm    = EXCLUDED.vendor_norm,
    product_norm   = EXCLUDED.product_norm,
    version_norm   = EXCLUDED.version_norm,
    version_scheme = EXCLUDED.version_scheme,
    updated_at     = EXCLUDED.updated_at
RETURNING id;

-- ListComponentsByVendorProduct returns the components of one raw
-- vendor/product pair — the I1b matcher read (exact_identifier /
-- canonical_product_range, ARCH-001 §3): the minimal matcher resolves the
-- affected version range over this set in application code. The I1b
-- (vendor, product) index was replaced by the normalised product index in
-- 00005, so this legacy read stays correct but is no longer indexed; the
-- I3 matching reads go through ListComponentsByVendorProductNorm.
-- name: ListComponentsByVendorProduct :many
SELECT id, asset_id, vendor, product, version, created_at
FROM components
WHERE vendor = @vendor AND product = @product
ORDER BY version;

-- ListComponentsByVendorProductNorm returns the components of one
-- normalised vendor/product pair — the inventory product index lookup
-- (ADR-012, ARCH-003 §4, IX components_product_idx ON (vendor_norm,
-- product_norm)) that serves the candidate pre-filter semi-join: the
-- matcher computes the alias closure of a CVE's (vendor, product) pairs
-- and resolves candidate components over the index. Rows are ordered by
-- natural_key for a deterministic candidate order. Deactivated rows are
-- returned like active ones — the matching engine decides what a
-- deactivated component may still match (ARCH-003 §1.2: components stay
-- referenceable when deactivated).
-- name: ListComponentsByVendorProductNorm :many
SELECT id, asset_id, vendor, product, version, created_at,
       cpe, purl, image, digest,
       vendor_norm, product_norm, version_norm, version_scheme,
       natural_key, updated_at, deactivated_at
FROM components
WHERE vendor_norm = @vendor_norm AND product_norm = @product_norm
ORDER BY natural_key;

-- ListComponentsByAsset returns every component of one asset — the
-- asset -> components read (ARCH-003 §1.2, IX components_asset_id_idx,
-- GET /assets/{id}/components): the full row set an asset's inventory
-- view and the WP-3.05 import preview project over. Rows are ordered by
-- natural_key (the import idempotency key) so the preview diff walks a
-- stable order; legacy NULL-key rows sort first. Deactivated components
-- stay listed — they remain historically referenceable (ARCH-003 §1.2).
-- name: ListComponentsByAsset :many
SELECT id, asset_id, vendor, product, version, created_at,
       cpe, purl, image, digest,
       vendor_norm, product_norm, version_norm, version_scheme,
       natural_key, updated_at, deactivated_at
FROM components
WHERE asset_id = @asset_id
ORDER BY natural_key;
