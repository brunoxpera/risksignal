-- export_source: the streaming signal read behind an export (ARCH-007 §1.2,
-- WP-6.02 / DEV-112).
--
-- SignalExportSource is the read the export.generate worker streams: a
-- full-scan variant of ListSignals (no pagination/LIMIT — the caller iterates
-- the pgx rows) reusing the same signal projection, filterable by the ch. 10.4
-- signal filter and ordered by the ch. 10.4 standard sort (priority ascending
-- P1→P4, then the next open SLA deadline, then the creation instant, with id
-- as the stable tiebreak). It is a pure read; it materialises nothing and is
-- not a second write path.

-- SignalExportSource returns every signal matching the frozen ch. 10.4 filter,
-- ordered by the §10.4 standard sort. Every filter is optional — pass NULL to
-- keep it open (the same sqlc.narg style as ListSignals) — and the object
-- scope is applied by the caller passing owner_id:
--   * priority/status/owner_id  → the signal's own columns;
--   * asset_id/asset_type       → the matched component's asset;
--   * product                   → the matched component's product;
--   * cve                       → the matched vulnerability's CVE id;
--   * source_id                 → a source that evidenced the vulnerability
--                                 (through evidences → raw_records);
--   * created_from/created_to   → the signal creation instant, [from, to);
--   * free_text                 → a case-insensitive substring over the
--                                 human-readable fields (cve, summary, vendor,
--                                 product, asset name);
--   * sla_state                 → the SLA clock state against @now (the
--                                 injected clock): breached (an open clock
--                                 past its effective deadline), open (an open
--                                 clock not yet breached), met (has clocks,
--                                 none open) or none (no clocks). The domain
--                                 validates the vocabulary; the effective
--                                 deadline adds the accumulated pause.
-- The next open SLA deadline used for the ordering is the minimum effective
-- deadline over the signal's unfulfilled clocks (NULLS LAST when there is
-- none); the effective deadline adds paused_seconds and, while paused, the
-- time since paused_at — the same arithmetic the SLA evaluator uses. Unlike a
-- working-list page this read is intentionally unbounded; export.max_rows
-- bounds it in the use case, never here.
-- name: SignalExportSource :many
SELECT
    rs.id,
    rs.match_id,
    rs.priority,
    rs.status,
    rs.owner,
    rs.due_at,
    rs.closed_at,
    rs.version,
    rs.rule_version,
    rs.factors,
    rs.created_at,
    v.cve_id,
    v.summary,
    m.method,
    m.confidence,
    c.vendor,
    c.product,
    c.version      AS component_version,
    a.id           AS asset_id,
    a.external_id  AS asset_external_id,
    a.type         AS asset_type,
    a.name         AS asset_name,
    a.environment  AS asset_environment,
    a.criticality  AS asset_criticality,
    a.exposure     AS asset_exposure
FROM risk_signals rs
JOIN matches m         ON m.id = rs.match_id
JOIN vulnerabilities v ON v.id = m.vulnerability_id
JOIN components c      ON c.id = m.component_id
JOIN assets a          ON a.id = c.asset_id
LEFT JOIN LATERAL (
    SELECT
        MIN(
            sc.deadline_at
            + make_interval(secs => sc.paused_seconds::double precision)
            + CASE WHEN sc.paused_at IS NOT NULL THEN (@now::timestamptz) - sc.paused_at ELSE interval '0' END
        ) FILTER (WHERE sc.fulfilled_at IS NULL)                                          AS next_deadline,
        COALESCE(bool_or(sc.fulfilled_at IS NULL), false)                                 AS has_open,
        COALESCE(bool_or(
            sc.fulfilled_at IS NULL
            AND sc.deadline_at
                + make_interval(secs => sc.paused_seconds::double precision)
                + CASE WHEN sc.paused_at IS NOT NULL THEN (@now::timestamptz) - sc.paused_at ELSE interval '0' END
                < @now::timestamptz
        ), false)                                                                         AS has_breached,
        count(*)                                                                          AS clock_count
    FROM sla_clocks sc
    WHERE sc.signal_id = rs.id
) sla ON true
WHERE (sqlc.narg('priority')::text IS NULL OR rs.priority = sqlc.narg('priority'))
  AND (sqlc.narg('status')::text IS NULL OR rs.status = sqlc.narg('status'))
  AND (sqlc.narg('owner_id')::text IS NULL OR rs.owner = sqlc.narg('owner_id'))
  AND (sqlc.narg('asset_id')::uuid IS NULL OR a.id = sqlc.narg('asset_id'))
  AND (sqlc.narg('asset_type')::text IS NULL OR a.type = sqlc.narg('asset_type'))
  AND (sqlc.narg('product')::text IS NULL OR c.product = sqlc.narg('product'))
  AND (sqlc.narg('cve')::text IS NULL OR v.cve_id = sqlc.narg('cve'))
  AND (sqlc.narg('source_id')::uuid IS NULL OR EXISTS (
        SELECT 1
        FROM evidences e
        JOIN raw_records rr ON rr.id = e.raw_record_id
        WHERE e.vulnerability_id = m.vulnerability_id
          AND rr.source_id = sqlc.narg('source_id')::uuid
      ))
  AND (sqlc.narg('created_from')::timestamptz IS NULL OR rs.created_at >= sqlc.narg('created_from'))
  AND (sqlc.narg('created_to')::timestamptz IS NULL OR rs.created_at < sqlc.narg('created_to'))
  AND (sqlc.narg('free_text')::text IS NULL OR (
        v.cve_id   ILIKE '%' || sqlc.narg('free_text') || '%'
        OR v.summary ILIKE '%' || sqlc.narg('free_text') || '%'
        OR c.vendor  ILIKE '%' || sqlc.narg('free_text') || '%'
        OR c.product ILIKE '%' || sqlc.narg('free_text') || '%'
        OR a.name    ILIKE '%' || sqlc.narg('free_text') || '%'
      ))
  AND (sqlc.narg('sla_state')::text IS NULL OR CASE sqlc.narg('sla_state')
        WHEN 'breached' THEN sla.has_breached
        WHEN 'open'     THEN sla.has_open AND NOT sla.has_breached
        WHEN 'met'      THEN sla.clock_count > 0 AND NOT sla.has_open
        WHEN 'none'     THEN sla.clock_count = 0
        ELSE false
      END)
ORDER BY rs.priority,
         sla.next_deadline NULLS LAST,
         rs.created_at,
         rs.id;
