-- evidences writes (ARCH-001 §1, ch. 6.1 Evidence, WP-1b.02; extended
-- vocabulary ARCH-002 §1/§3, WP-2.03b).
--
-- Evidence rows are immutable source statements: no update, no delete.
-- The type column is a plain text column (no CHECK constraint), so the
-- vocabulary is additive and the insert path needs no per-type special
-- casing: the I2 types nvd_statement / reference / kev_removed (ARCH-002
-- §1/§2) flow through the same statement as the I1b types
-- synthetic_statement / cvss / kev / epss, deduplicated by the natural key
-- (raw_record_id, type, value_hash) exactly like every other type.

-- InsertEvidence stores one source statement per (vulnerability, raw record,
-- type). The natural key (raw_record_id, type, value_hash) makes repeated
-- ingestion a no-op (ARCH-001 §3 step 3); observed_at comes from the
-- injected clock.
-- name: InsertEvidence :exec
INSERT INTO evidences (vulnerability_id, raw_record_id, type, value, value_hash, observed_at)
VALUES (@vulnerability_id, @raw_record_id, @type, @value, @value_hash, @observed_at)
ON CONFLICT (raw_record_id, type, value_hash) DO NOTHING;
