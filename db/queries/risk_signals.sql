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

-- InsertDemoRiskSignal writes one fully-specified signal row of the I4 demo
-- fixture (WP-4.08 / DEV-083, ARCH-004 §8): unlike InsertRiskSignal it
-- supplies the id, status, version and closed_at explicitly, so the
-- fixture owns stable, reproducible identities and statuses across runs
-- (the demo seed is deterministic by construction). It is operator tooling
-- of the demo command only — the production create path is InsertRiskSignal
-- behind CreateSignal (the id/status/version column defaults stay the
-- production contract, ARCH-001 §2). factors carries the contributing
-- factor set; created_at/occurred instants come from the injected clock.
-- name: InsertDemoRiskSignal :one
INSERT INTO risk_signals (
    id, match_id, priority, status, owner, due_at, closed_at, version, rule_version, factors, created_at
)
VALUES (
    @id, @match_id, @priority, @status, @owner, @due_at, @closed_at, @version, @rule_version, @factors, @created_at
)
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

-- The I4 signal writes (ARCH-004 §2.1/§2.3/§3, WP-4.03 / DEV-073). Every
-- mutating statement is guarded on the optimistic-lock version the client
-- read (WHERE id = $1 AND version = $2): a stale version matches zero rows,
-- which the command layer maps to a conflict (HTTP 409, ch. 7.3), never a
-- silent overwrite. The statement bumps version, so a losing writer's next
-- attempt uses the fresh value. RETURNING * hands the stored row back for
-- the caller's mapping in one round trip.

-- GetRiskSignalByID returns the plain stored signal row (no joins) — the
-- read the I4 command layer takes before it applies a guarded transition
-- and the canonical row for the writes' RETURNING shape. A missing row is a
-- not-found error.
-- name: GetRiskSignalByID :one
SELECT *
FROM risk_signals
WHERE id = @id;

-- TransitionRiskSignal is the ch. 6.3 status change of ARCH-004 §2: it sets
-- the new status and the closed_at stamp (the entry instant of a closed
-- state, NULL when leaving to a non-closed state or reopening) under the
-- optimistic lock. The domain state machine (domain.Transition) rules which
-- edges are legal; this statement guards the row is still at the version the
-- caller read and bumps it. Zero rows = a stale version (conflict).
-- name: TransitionRiskSignal :one
UPDATE risk_signals SET
    status    = @status,
    closed_at = @closed_at,
    version   = version + 1
WHERE id = @id AND version = @expected_version
RETURNING *;

-- OverrideRiskSignalPriority is the manual re-prioritisation of ARCH-004 §3
-- (ADR-015 mirror): it sets the effective priority, preserves the computed
-- value in auto_priority and stamps the mandatory reason/actor/time — the
-- four override columns are all-set together (the schema CHECK enforces the
-- all-or-nothing invariant). The caller supplies the computed auto_priority
-- it read; the optimistic lock rejects a stale write.
-- name: OverrideRiskSignalPriority :one
UPDATE risk_signals SET
    priority          = @priority,
    auto_priority     = @auto_priority,
    override_reason   = @override_reason,
    override_actor_id = @override_actor_id,
    override_at       = @override_at,
    version           = version + 1
WHERE id = @id AND version = @expected_version
RETURNING *;

-- RevertRiskSignalPriority restores the computed priority from auto_priority
-- and clears the four override columns in one guarded write (ARCH-004 §3).
-- priority = auto_priority reads the pre-update value, so the computed value
-- is restored before the override quartet is cleared; the row ends purely
-- computed (all four NULL — the CHECK holds). The optimistic lock rejects a
-- stale write.
-- name: RevertRiskSignalPriority :one
UPDATE risk_signals SET
    priority          = auto_priority,
    auto_priority     = NULL,
    override_reason   = NULL,
    override_actor_id = NULL,
    override_at       = NULL,
    version           = version + 1
WHERE id = @id AND version = @expected_version
RETURNING *;

-- AssignRiskSignalOwner assigns the (opaque, until I5a) owner principal under
-- the optimistic lock (ARCH-004 §2.1). "" clears the owner (NULL).
-- name: AssignRiskSignalOwner :one
UPDATE risk_signals SET
    owner   = @owner,
    version = version + 1
WHERE id = @id AND version = @expected_version
RETURNING *;

-- RecomputeRiskSignalPriority persists the outcome of a targeted priority
-- recompute (ARCH-004 §5, ch. 9.5) in one write: the freshly rebuilt factor
-- set, the rule version the recompute ran under and the recomputed computed
-- priority. The override-survival mirror of §3 is enforced in the SET list:
-- for a purely computed signal (auto_priority IS NULL) the effective
-- priority is updated and auto_priority stays NULL; for an overridden signal
-- the computed value updates auto_priority only and the effective priority
-- (the human decision) is left untouched. The statement is not
-- version-guarded — the changed-only comparison of the command keeps an
-- identical recompute from reaching it at all — and it bumps version so a
-- concurrent guarded write still sees a fresh token.
-- name: RecomputeRiskSignalPriority :one
UPDATE risk_signals SET
    priority      = CASE WHEN auto_priority IS NULL THEN @priority::text ELSE priority END,
    auto_priority = CASE WHEN auto_priority IS NULL THEN NULL ELSE @priority::text END,
    rule_version  = @rule_version,
    factors       = @factors,
    version       = version + 1
WHERE id = @id
RETURNING *;

-- MarkRiskSignalEscalated records the first P1 escalation instant (ARCH-004
-- §4.4). The escalated_at IS NULL guard makes it set-once: the first
-- escalation matches the row, every later call matches zero rows (the
-- adapter reports "already escalated"), so a reminder cadence can never
-- re-stamp the instant. Zero rows is not an error.
-- name: MarkRiskSignalEscalated :one
UPDATE risk_signals SET
    escalated_at = @escalated_at,
    version      = version + 1
WHERE id = @id AND escalated_at IS NULL
RETURNING *;

-- ListOpenRecomputeTargets returns the id and stored factor-set of every
-- open (non-closed) signal — the fan-in read of a ruleset publish (ARCH-004
-- §5: "a rule-version publish enqueues a batched recompute over all open
-- signals"). The closed states (resolved/accepted/not_affected) are excluded:
-- a closed signal is never silently changed (its recompute proposes a reopen
-- instead, §5) and is not part of the publish fan-out. Ordered by id. No open
-- signal yields no rows, never an error.
-- name: ListOpenRecomputeTargets :many
SELECT id, factors
FROM risk_signals
WHERE status NOT IN ('resolved', 'accepted', 'not_affected')
ORDER BY id;

-- ListRecomputeTargetsByVulnerabilityIDs returns the id and stored
-- factor-set of every signal whose match references one of the given
-- vulnerability row ids — the fan-in read of a matching.recompute run
-- (ARCH-004 §5: the run enqueues a per-signal priority.recompute for the
-- affected signals). ids is a jsonb array of canonical uuid strings; at most
-- one row per signal (UQ match_id) and ordered by id. An id-less query
-- returns no rows, never an error.
-- name: ListRecomputeTargetsByVulnerabilityIDs :many
SELECT DISTINCT rs.id, rs.factors
FROM risk_signals rs
JOIN matches m ON m.id = rs.match_id
WHERE m.vulnerability_id IN (SELECT value::uuid FROM jsonb_array_elements_text(@ids::jsonb))
ORDER BY rs.id;
