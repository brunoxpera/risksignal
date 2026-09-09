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
-- injected clock. The statement returns the evidence id — the newly
-- inserted one, or the already existing one of an identical earlier
-- statement (the I2 forward-note: the reprocess path links the returned id
-- into quarantine.resolved_evidence_id, ARCH-003 §7).
-- name: InsertEvidence :one
WITH inserted AS (
    INSERT INTO evidences (vulnerability_id, raw_record_id, type, value, value_hash, observed_at)
    VALUES (@vulnerability_id, @raw_record_id, @type, @value, @value_hash, @observed_at)
    ON CONFLICT (raw_record_id, type, value_hash) DO NOTHING
    RETURNING id
)
SELECT id FROM inserted
UNION ALL
SELECT id FROM evidences
WHERE raw_record_id = @raw_record_id AND type = @type AND value_hash = @value_hash
LIMIT 1;

-- ListPreviousKEVCVEs loads the CVE ids of the source's previously stored
-- KEV full set (DEV-041, ARCH-002 §2.2): the kev evidences attached to the
-- source's latest stored raw record other than the pass's own
-- (exclude_raw_record_id — the raw record currently being normalised, whose
-- evidence rows do not exist yet or belong to this pass, not to the
-- previous catalog). The normalise use cases feed the set to the KEV
-- adapter through NormalizeInput.PreviousKEVCVEs, which historises every
-- CVE absent from the new catalog as a kev_removed evidence (ch. 8.3:
-- removals are historised, never silently dropped).
--
-- The previous set is scoped to the previous raw record — not the union of
-- all stored ones: a CVE removed by an earlier revision is recorded as
-- kev_removed there (type != 'kev', filtered out), so it stays removed and
-- is not re-historised by every later catalog. A source with no prior raw
-- record (the first import) yields no rows and the pass emits no removals.
-- name: ListPreviousKEVCVEs :many
SELECT DISTINCT (e.value->>'cve_id')::text AS cve_id
FROM evidences e
WHERE e.type = 'kev'
  AND e.value->>'cve_id' IS NOT NULL
  AND e.raw_record_id = (
      SELECT r.id
      FROM raw_records r
      WHERE r.source_id = @source_id
        AND r.id <> @exclude_raw_record_id
      ORDER BY r.fetched_at DESC, r.id DESC
      LIMIT 1
  )
ORDER BY cve_id;
