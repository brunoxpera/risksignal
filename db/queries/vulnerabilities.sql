-- vulnerabilities ingest (ARCH-001 §1, ch. 7.1, WP-1b.02).
--
-- I1b carries only identity + summary; the full NVD description/CVSS-metrics/
-- references arrive with I2.

-- UpsertVulnerability inserts or refreshes a vulnerability by its natural
-- key cve_id and returns its id (ARCH-001 §3 step 3: upsert, idempotent by
-- UQ (cve_id)). On refresh, published_at keeps the original publication
-- date; summary and modified_at follow the latest statement.
-- name: UpsertVulnerability :one
INSERT INTO vulnerabilities (cve_id, summary, published_at, modified_at)
VALUES (@cve_id, @summary, @published_at, @modified_at)
ON CONFLICT (cve_id) DO UPDATE SET
    summary     = EXCLUDED.summary,
    modified_at = EXCLUDED.modified_at
RETURNING id;
