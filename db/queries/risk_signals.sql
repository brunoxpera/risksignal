-- risk_signals: the CreateSignal write and the working-list reads
-- (ARCH-001 §1 and §4, WP-1b.02).

-- InsertRiskSignal creates one signal per match; the UQ (match_id) enforces
-- that at the schema level (command-level idempotency, ARCH-001 §2). status
-- ('new') and version (1, the optimistic-lock start value) come from the
-- column defaults; factors stores the contributing factors so a later
-- recompute can decide whether anything changed (ch. 9.5). created_at comes
-- from the injected clock.
-- name: InsertRiskSignal :one
INSERT INTO risk_signals (match_id, priority, owner, due_at, closed_at, rule_version, factors, created_at)
VALUES (@match_id, @priority, @owner, @due_at, @closed_at, @rule_version, @factors, @created_at)
RETURNING *;

-- GetSignalByMatchID returns the id of the signal of one match, if any — the
-- existence check of ARCH-001 §3 step 5 (per match without a signal: run the
-- CreateSignal command).
-- name: GetSignalByMatchID :one
SELECT id
FROM risk_signals
WHERE match_id = @match_id;

-- GetSignalByID returns the readable signal detail: the signal joined with
-- its match, vulnerability, component and asset (ARCH-001 §4 getSignal).
-- name: GetSignalByID :one
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
WHERE rs.id = @id;

-- ListSignals is the working-list read (ARCH-001 §4 listSignals): priority
-- ascending P1→P4, then created_at with id as the stable tiebreak (ch. 10.4;
-- the SLA-deadline part of the ordering arrives with I4). priority and
-- status filter optionally — pass NULL to keep a filter open.
-- name: ListSignals :many
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
WHERE (sqlc.narg('priority')::text IS NULL OR rs.priority = sqlc.narg('priority'))
  AND (sqlc.narg('status')::text IS NULL OR rs.status = sqlc.narg('status'))
ORDER BY rs.priority, rs.created_at, rs.id
LIMIT @max_rows;
