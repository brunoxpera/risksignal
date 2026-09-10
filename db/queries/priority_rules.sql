-- priority_rules: the versioned, copy-on-write ruleset snapshot statements
-- (ARCH-004 §1, WP-4.03 / DEV-073).
--
-- The priority rules are a single versioned ruleset snapshot: a publish
-- writes the whole P1..P4 snapshot copy-on-write at version = MAX(version)+1
-- (UQ (rule_id, version) makes each row immutable), and the effective
-- snapshot for evaluation is WHERE version = (SELECT MAX(version)). A signal
-- references exactly one snapshot through its rule_version, so "den
-- verwendeten Regelstand" (ch. 9.3) is one immutable value. The read side
-- returns the whole effective snapshot; the write side is the admin,
-- audited PublishPriorityRules command (WP-4.04).

-- PublishPriorityRules inserts one full ruleset snapshot — the passed rule
-- rows (rule_id, definition, enabled) — at next = MAX(version)+1, all
-- sharing one effective_from/reason/actor_id/created_at (the injected clock
-- and the audited publisher). The version is computed once per statement
-- from the current MAX: the uncorrelated subquery is evaluated a single
-- time, so the whole snapshot lands at one version and UQ (rule_id, version)
-- guards a concurrent publish (a race surfaces as a unique violation for the
-- command layer to map, never a torn snapshot). RETURNING version lets the
-- caller stamp the new effective version without a second read.
-- name: PublishPriorityRules :many
INSERT INTO priority_rules (rule_id, version, definition, enabled, effective_from, reason, actor_id, created_at)
SELECT
    v.rule_id,
    (SELECT COALESCE(MAX(version), 0) + 1 FROM priority_rules),
    v.definition,
    v.enabled,
    @effective_from,
    @reason,
    @actor_id,
    @created_at
FROM (VALUES
    (@p1_rule_id::text, @p1_definition::jsonb, @p1_enabled::boolean),
    (@p2_rule_id::text, @p2_definition::jsonb, @p2_enabled::boolean),
    (@p3_rule_id::text, @p3_definition::jsonb, @p3_enabled::boolean),
    (@p4_rule_id::text, @p4_definition::jsonb, @p4_enabled::boolean)
) AS v(rule_id, definition, enabled)
RETURNING version;

-- ListEffectivePriorityRules returns the whole effective snapshot — every
-- rule row at version = MAX(version) — ordered by rule_id (P1→P4) for a
-- deterministic read. The evaluator applies them first-match-wins; disabled
-- rows are returned too (a disabled rule is inert and the caller's evaluator
-- skips it). An empty table yields no rows, never an error.
-- name: ListEffectivePriorityRules :many
SELECT *
FROM priority_rules
WHERE version = (SELECT MAX(version) FROM priority_rules)
ORDER BY rule_id;

-- GetEffectivePriorityRulesVersion returns the current effective ruleset
-- version (MAX(version), the snapshot in force). An empty table reads 0 —
-- the "no ruleset published yet" sentinel the create path treats as "use the
-- I1b stamp" until the first publish.
-- name: GetEffectivePriorityRulesVersion :one
SELECT COALESCE(MAX(version), 0)::integer AS version
FROM priority_rules;
