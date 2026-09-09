-- 00006_components_contract.sql — I3 inventory & matching, Contract phase
-- (ARCH-003 §1.2/§1.3, implementation concept ch. 7.4
-- Expand-Migrate-Contract; WP-3.03b / DEV-057). Migration 00005 was the
-- Expand phase: the normalised comparison keys and the import idempotency
-- key arrived nullable, the legacy rows were backfilled with safe defaults
-- and the pre-I3 4-column InsertComponent write path stayed live. 00006 is
-- the Contract phase, applied after DEV-056 switched the write path to the
-- I3 natural-key upsert — the pipeline stays green because every row
-- written from the switch on carries the comparison keys and the natural
-- key (migration 00005's backfill covers the pre-I3 rows):
--
--   * SET NOT NULL on components.vendor_norm / product_norm / natural_key
--     — the I3 write path (db/queries/components.sql, InsertComponent)
--     supplies them unconditionally, the backfilled legacy rows carry
--     them, and a future pre-I3 4-column write is rejected loudly instead
--     of landing an unmatchable, non-idempotent row;
--   * components_identifier_check — the matchability contract of ARCH-003
--     §1.2/§1.3 ("a row must carry at least one identity"): a component is
--     matchable when it carries an identity original — cpe, purl, digest
--     or image, image included per the DEV-044 reconciliation (the domain
--     treats an image-only component as valid, hasAnyIdentifier in
--     internal/domain/component.go) — or the normalised vendor/product
--     pair. Every branch is trimmed-then-non-empty and NULL-safe
--     (COALESCE(btrim(col), '') <> '' — a SQL CHECK passes on NULL, so a
--     bare btrim(col) <> '' would let the nullable identifier originals
--     through vacuously), aligned with the domain's presence rule
--     (internal/domain/
--     naturalkey.go: empty/NULL identifiers are never an identity — an
--     identifier-less row must not pass a whitespace-only value): a
--     whitespace-only cpe/purl/digest/image or a blank vendor_norm/
--     product_norm pair carries no identity. The raw vendor/product/
--     version columns stay untouched (NOT NULL since I1b; originals are
--     preserved verbatim, ARCH-003 §1.2).
--
-- The version_scheme CHECK, UQ (asset_id, natural_key), the inventory
-- product index and the asset_id index landed in 00005 and are unchanged.
-- The CHECK here must not reject the I3 write path's rows: every
-- InsertComponent write supplies trimmed NFKC+lowercase comparison keys of
-- the row identity (vendor_norm/product_norm of a non-empty
-- vendor/product), so a row of the vendor/product fallback passes the pair
-- branch, and an identity-carrying row (cpe/purl/digest/image) passes its
-- own branch even when vendor/product are empty.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- Contract: the comparison keys and the import idempotency key are no
-- longer optional. Every row — backfilled legacy or written through the I3
-- path since the DEV-056 switch — carries them; a write that omits them
-- fails loudly (not-null violation) instead of silently producing a row
-- that cannot participate in UQ (asset_id, natural_key) or the inventory
-- product index.
ALTER TABLE components
    ALTER COLUMN vendor_norm  SET NOT NULL,
    ALTER COLUMN product_norm SET NOT NULL,
    ALTER COLUMN natural_key  SET NOT NULL;

-- The matchability contract (ARCH-003 §1.2/§1.3): every component row
-- carries at least one identity — the trimmed-then-non-empty cpe, purl,
-- digest or image original (image included per the DEV-044 reconciliation)
-- or the normalised vendor/product comparison key pair. The constraint
-- mirrors the domain presence rule hasAnyIdentifier (component.go) and the
-- natural-key derivation (naturalkey.go): whitespace is not an identity,
-- so every branch trims before testing (COALESCE keeps the nullable
-- cpe/purl/digest/image branches three-valued-logic safe — a CHECK passes
-- on NULL, so a bare btrim(cpe) <> '' would let a NULL original through
-- vacuously; COALESCE(btrim(col), '') turns NULL into '' and the branch
-- into false). A blank vendor_norm/product_norm pair is rejected unless
-- an identity original carries the row.
ALTER TABLE components
    ADD CONSTRAINT components_identifier_check CHECK (
        COALESCE(btrim(cpe), '') <> ''
        OR COALESCE(btrim(purl), '') <> ''
        OR COALESCE(btrim(digest), '') <> ''
        OR COALESCE(btrim(image), '') <> ''
        OR (COALESCE(btrim(vendor_norm), '') <> '' AND COALESCE(btrim(product_norm), '') <> '')
    );

COMMENT ON CONSTRAINT components_identifier_check ON components IS
    'Matchability contract (ARCH-003 §1.2/§1.3): each row carries at least one identity — a trimmed-then-non-empty cpe/purl/digest/image original (image included, DEV-044) or the trimmed-then-non-empty vendor_norm/product_norm pair — mirroring domain hasAnyIdentifier; whitespace is not an identity';
COMMENT ON COLUMN components.vendor_norm IS
    'Normalised vendor comparison key (NFKC + trim + lowercase at write time, no alias — aliases resolve at match time, ARCH-003 §2); NOT NULL from the 00006 contract phase on';
COMMENT ON COLUMN components.product_norm IS
    'Normalised product comparison key (NFKC + trim + lowercase at write time, no alias); NOT NULL from the 00006 contract phase on';
COMMENT ON COLUMN components.natural_key IS
    'Deterministic import idempotency key (UQ asset_id, natural_key, ARCH-003 §1.3): sha-256 of the strongest identifier (cpe > purl > digest > image > vendor/product/version), prefix-tagged — legacy pre-I3 rows carry a ''legacy:'' md5 placeholder; NOT NULL from the 00006 contract phase on';
