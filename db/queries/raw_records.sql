-- raw_records ingest (ARCH-001 §1, ADR-013, WP-1b.02).
--
-- The synthetic source stores one unchanged document per run (ch. 8.1 step
-- 4); re-running the source must not duplicate it (natural-key idempotency).

-- InsertRawRecord stores the unchanged source document and returns the id of
-- the row — the newly inserted one, or the already existing one when
-- (source_id, external_id, content_hash) is present (ARCH-001 §3 step 2:
-- idempotent insert, ON CONFLICT DO NOTHING on the natural key).
-- name: InsertRawRecord :one
WITH inserted AS (
    INSERT INTO raw_records (source_id, external_id, content_hash, payload, fetched_at)
    VALUES (@source_id, @external_id, @content_hash, @payload, @fetched_at)
    ON CONFLICT (source_id, external_id, content_hash) DO NOTHING
    RETURNING id
)
SELECT id FROM inserted
UNION ALL
SELECT id FROM raw_records
WHERE source_id = @source_id AND external_id = @external_id AND content_hash = @content_hash
LIMIT 1;
