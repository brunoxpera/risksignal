-- raw_records ingest (ARCH-001 §1, ADR-013, WP-1b.02; bytea payload +
-- content_encoding ARCH-002 §3, WP-2.03b).
--
-- From migration 00004 on a raw record is the unchanged source
-- document/file bytes (bytea): the compressed EPSS file, the KEV catalog,
-- the NVD page — with content_encoding ('identity' | 'gzip' | 'json')
-- written by the fetching adapter so a stored payload is self-describing
-- for reprocess. The sqlc layer maps the payload column to []byte, so the
-- Go signatures of the I1b callers are unchanged (the 00004 backfill
-- converted the pre-existing jsonb rows to their UTF-8 JSON bytes and
-- stamped them 'json').
--
-- The synthetic source stores one unchanged document per run (ch. 8.1 step
-- 4); re-running the source must not duplicate it (natural-key idempotency).

-- InsertRawRecord stores the unchanged source document and returns the id of
-- the row — the newly inserted one, or the already existing one when
-- (source_id, external_id, content_hash) is present (ARCH-001 §3 step 2:
-- idempotent insert, ON CONFLICT DO NOTHING on the natural key). payload is
-- the raw document bytes; content_encoding describes them (NULL when the
-- caller does not set it, e.g. the I1b synthetic insert path).
-- name: InsertRawRecord :one
WITH inserted AS (
    INSERT INTO raw_records (source_id, external_id, content_hash, payload, content_encoding, fetched_at)
    VALUES (@source_id, @external_id, @content_hash, @payload, @content_encoding, @fetched_at)
    ON CONFLICT (source_id, external_id, content_hash) DO NOTHING
    RETURNING id
)
SELECT id FROM inserted
UNION ALL
SELECT id FROM raw_records
WHERE source_id = @source_id AND external_id = @external_id AND content_hash = @content_hash
LIMIT 1;

-- GetRawRecordByID loads one raw document with its payload bytes and
-- content_encoding by id — the read the quarantine reprocess path starts
-- from (ARCH-002 §4: re-read the raw record via raw_record_id and re-run
-- the normaliser over its payload).
-- name: GetRawRecordByID :one
SELECT id, source_id, external_id, content_hash, payload, content_encoding, fetched_at
FROM raw_records
WHERE id = @id;
