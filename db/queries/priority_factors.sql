-- priority_factors: the read statements of the priority factor rebuild
-- (ARCH-004 §5, WP-4.04b / DEV-077).
--
-- RecomputePriority rebuilds a signal's PriorityFactors fresh from its
-- persisted context: the linked match's method/confidence (ADR-015), the
-- vulnerability's latest KEV/CVSS/EPSS evidence and the owning asset's
-- criticality/exposure. Both reads below are plain, transaction-free
-- lookups — the recompute reads before it decides whether anything changed
-- (changed-only persist, ch. 9.5), so it never opens a transaction on a
-- no-op.

-- GetSignalPriorityFactorSource resolves the identity + asset context of one
-- signal's factor rebuild: the match's method (and the vulnerability it
-- links to) and the owning asset's criticality/exposure — the
-- signal -> match -> vulnerability/component -> asset join chain. The
-- confidence is NOT read here: ADR-015 derives it from the authoritative
-- method, so the rebuild re-derives it instead of trusting a stored copy. A
-- missing signal (or a broken join chain) is pgx.ErrNoRows.
-- name: GetSignalPriorityFactorSource :one
SELECT
    m.vulnerability_id,
    m.method,
    v.cve_id,
    a.criticality,
    a.exposure
FROM risk_signals rs
JOIN matches m         ON m.id = rs.match_id
JOIN vulnerabilities v ON v.id = m.vulnerability_id
JOIN components c      ON c.id = m.component_id
JOIN assets a          ON a.id = c.asset_id
WHERE rs.id = @id;

-- ListVulnerabilityFactorEvidence returns the latest evidence row of each
-- factor type (cvss, kev, kev_removed, epss) of one vulnerability — the
-- prioritisation reads the recompute rebuilds KEV/CVSS/EPSS from (ARCH-004
-- §5, ARCH-002 §3). DISTINCT ON keeps the newest row per type (observed_at,
-- then id, DESC), so a re-emitted statement under the same type never masks
-- the newest one. Non-factor evidence types (nvd_statement, reference, …)
-- carry no factor and are never selected. An empty result (a vulnerability
-- with no factor evidence) yields no rows, never an error.
-- name: ListVulnerabilityFactorEvidence :many
SELECT DISTINCT ON (e.type) e.type, e.value, e.observed_at
FROM evidences e
WHERE e.vulnerability_id = @vulnerability_id
  AND e.type IN ('cvss', 'kev', 'kev_removed', 'epss')
ORDER BY e.type, e.observed_at DESC, e.id DESC;
