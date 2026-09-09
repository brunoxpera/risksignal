-- vulnerabilities ingest (ARCH-001 §1, ch. 7.1, WP-1b.02; full NVD fields
-- ARCH-002 §2.1/§3, WP-2.03b).
--
-- I1b carries only identity + summary; the full NVD description / CVSS
-- metrics / references / cpe_config arrive with I2. All four columns are
-- nullable so the I1b rows and the I2 KEV skeleton rows stay valid.
--
-- "references" is a reserved keyword in PostgreSQL and is therefore always
-- quoted as "references" in the statements below — in the INSERT column
-- list, in the ON CONFLICT refresh and in the read's SELECT list.

-- UpsertVulnerability inserts or refreshes a vulnerability by its natural
-- key cve_id and returns its id (ARCH-001 §3 step 3: upsert, idempotent by
-- UQ (cve_id)). On refresh, published_at keeps the original publication
-- date; summary, description, modified_at and the NVD fields (cvss,
-- "references", cpe_config) follow the latest statement (ch. 8.2). The
-- caller passes NULL for the fields a statement does not carry (e.g. a KEV
-- skeleton row carries summary only) — upserting such a row never invents
-- NVD fields, and the next NVD statement refreshes them again.
-- name: UpsertVulnerability :one
INSERT INTO vulnerabilities (cve_id, summary, description, published_at, modified_at, cvss, "references", cpe_config)
VALUES (@cve_id, @summary, @description, @published_at, @modified_at, @cvss, @nvd_references, @cpe_config)
ON CONFLICT (cve_id) DO UPDATE SET
    summary      = EXCLUDED.summary,
    description  = EXCLUDED.description,
    modified_at  = EXCLUDED.modified_at,
    cvss         = EXCLUDED.cvss,
    "references" = EXCLUDED."references",
    cpe_config   = EXCLUDED.cpe_config
RETURNING id;

-- GetVulnerabilityByCveID loads one vulnerability with its NVD fields by
-- natural key — the read an ingester uses to check whether a skeleton row
-- already exists before upserting (e.g. KEV arriving before NVD, ARCH-002
-- §2.2: the skeleton is only created when the CVE is not yet present) and
-- the read the extended-upsert round trip is asserted against.
-- name: GetVulnerabilityByCveID :one
SELECT id, cve_id, summary, description, published_at, modified_at, cvss, "references", cpe_config
FROM vulnerabilities
WHERE cve_id = @cve_id;

-- Matching-side reads of the vulnerabilities table (ARCH-003 §3/§5,
-- WP-3.09/DEV-065): the vulnerability-side reads of the matching runs —
-- the reverse pair read of matching.rebuild (ListVulnerabilitiesByPairs)
-- and the by-id batch read of matching.recompute (ListVulnerabilitiesByIDs).
-- Both return the row identity plus the raw NVD configurations block
-- (cpe_config) the adapter decomposes into the affected-product
-- statements of the run (the raw block is stored verbatim by the I2
-- ingest; the decomposition — the WP-3.07 statement decomposition — is
-- an adapter concern, never a stored column).

-- ListVulnerabilitiesByPairs returns the vulnerabilities whose stored
-- NVD configurations block (vulnerabilities.cpe_config, the verbatim raw
-- block of the I2 ingest) carries a cpeMatch criteria whose CPE 2.3
-- vendor/product pair equals one of the given raw normalised pairs
-- (pairs is a jsonb array of two-string arrays [vendor, product]) — the
-- reverse of the candidate pre-filter over the inventory-driven pair set
-- of a matching.rebuild component page (ADR-012, ARCH-003 §5: no
-- CVE-driven fan-out, the read is bounded by the component set). Each
-- row appears once, ordered ascending by id. The alias closure is the
-- caller's job — the run queries the closure-expanded pair set — so the
-- implementation matches the raw stored criteria pairs only (a CVE whose
-- raw pair is an alias variant is found through the closed query pair of
-- its canonical). The criteria comparison folds case like the stored
-- normalised keys; the returned cpe_config block is decomposed into the
-- affected-product statements by the adapter (rows the SQL filter lets
-- through on a raw criteria pair that the statement decomposition does
-- not render — a non-vulnerable or negated cpeMatch — decompose into no
-- pair and are intersected away by the run).
-- name: ListVulnerabilitiesByPairs :many
SELECT DISTINCT v.id, v.cve_id, v.cpe_config
FROM vulnerabilities v
WHERE v.cpe_config IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(@pairs::jsonb) AS p,
           jsonb_array_elements_text(
               jsonb_path_query_array(v.cpe_config, '$[*].nodes[*].cpeMatch[*].criteria')
               || jsonb_path_query_array(v.cpe_config, '$.nodes[*].cpeMatch[*].criteria')
           ) AS criteria
      WHERE lower(split_part(criteria, ':', 4)) = lower(p->>0)
        AND lower(split_part(criteria, ':', 5)) = lower(p->>1)
  )
ORDER BY v.id;

-- ListVulnerabilitiesByIDs returns the rows of the given vulnerability
-- ids, ascending by id — the recompute batch read: the pre-filtered
-- vulnerability id list of one matching.recompute job resolved into
-- statement-bearing rows (ids is a jsonb array of canonical uuid
-- strings). Vulnerabilities are never deleted, so a missing id is an
-- enqueuer bug the adapter reports as not-found. Rows without a
-- cpe_config block (I1b/KEV skeleton rows) come back with cpe_config NULL
-- and decompose into no statements — they resolve no candidates and
-- spawn no matching work.
-- name: ListVulnerabilitiesByIDs :many
SELECT id, cve_id, cpe_config
FROM vulnerabilities
WHERE id IN (SELECT value::uuid FROM jsonb_array_elements_text(@ids::jsonb))
ORDER BY id;
