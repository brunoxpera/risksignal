-- components: seed write + the matcher read (ARCH-001 §1, ADR-015,
-- WP-1b.02).

-- InsertComponent seeds one component row for an asset (vendor/product/
-- version only in I1b; CPE, purl and image/digest arrive with I3) and
-- returns its id.
-- name: InsertComponent :one
INSERT INTO components (asset_id, vendor, product, version)
VALUES (@asset_id, @vendor, @product, @version)
RETURNING id;

-- ListComponentsByVendorProduct returns the components of one vendor/product
-- pair — the I1b matcher read (exact_identifier / canonical_product_range,
-- ARCH-001 §3): the minimal matcher resolves the affected version range over
-- this set in application code.
-- name: ListComponentsByVendorProduct :many
SELECT id, asset_id, vendor, product, version, created_at
FROM components
WHERE vendor = @vendor AND product = @product
ORDER BY version;
