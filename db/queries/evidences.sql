-- evidences writes (ARCH-001 §1, ch. 6.1 Evidence, WP-1b.02).
--
-- Evidence rows are immutable source statements: no update, no delete.

-- InsertEvidence stores one source statement per (vulnerability, raw record,
-- type). The natural key (raw_record_id, type, value_hash) makes repeated
-- ingestion a no-op (ARCH-001 §3 step 3); observed_at comes from the
-- injected clock.
-- name: InsertEvidence :exec
INSERT INTO evidences (vulnerability_id, raw_record_id, type, value, value_hash, observed_at)
VALUES (@vulnerability_id, @raw_record_id, @type, @value, @value_hash, @observed_at)
ON CONFLICT (raw_record_id, type, value_hash) DO NOTHING;
