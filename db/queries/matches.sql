-- matches: the method-led match statements (ARCH-001 §1 matches, §3 step 4,
-- ADR-015; extended ARCH-003 §3, WP-3.03b / DEV-057). Matching is
-- method-led: the method is authoritative and confidence plus the derived
-- sort-rank score follow from it through the versioned ADR-015 mapping —
-- they are never stored or set independently. UQ (vulnerability_id,
-- component_id, rule_version) makes a re-run idempotent: the insert
-- returns the canonical row id (new or already existing) and a heal run
-- never duplicates.

-- InsertMatch records a method-led match and returns its id — the newly
-- inserted one, or the already existing one when (vulnerability_id,
-- component_id, rule_version) is present. Re-running the source inserts
-- nothing twice (ARCH-001 §3 step 4), and a healing run still learns the id
-- of an earlier match. created_at comes from the injected clock.
--
-- The I3 extension (ARCH-003 §3, ADR-015) carries the decision-rule state:
-- reasons is the auditable TR-007 rationale list (jsonb, '[]' for purely
-- computed rows — the schema default), decision_rule_id references the
-- decision rule that produced the match (an exclusion or an override —
-- NULL for purely computed matches), and auto_method/auto_confidence/
-- auto_score preserve the raw computed triple when a decision rule
-- overrode the match, so the override stays reversible (ch. 9.3 "der
-- berechnete Ausgangswert bleibt sichtbar"). Only an override sets the
-- auto_* columns; an exclude emits a visible no_match referencing the rule.
-- name: InsertMatch :one
WITH inserted AS (
    INSERT INTO matches (
        vulnerability_id, component_id, method, score, confidence, rule_version, created_at,
        reasons, decision_rule_id, auto_method, auto_confidence, auto_score
    )
    VALUES (
        @vulnerability_id, @component_id, @method, @score, @confidence, @rule_version, @created_at,
        @reasons, @decision_rule_id, @auto_method, @auto_confidence, @auto_score
    )
    ON CONFLICT (vulnerability_id, component_id, rule_version) DO NOTHING
    RETURNING id
)
SELECT id FROM inserted
UNION ALL
SELECT id FROM matches
WHERE vulnerability_id = @vulnerability_id AND component_id = @component_id AND rule_version = @rule_version
LIMIT 1;

-- ListMatchesByVulnerabilityComponent returns the full match history of
-- one (vulnerability_id, component_id) pair — every rule version the pair
-- was ever matched under, newest ruleset first (a rebuild or recompute
-- under a new rule version adds a row rather than replacing the old one:
-- UQ (vulnerability_id, component_id, rule_version) keeps the history
-- versioned, ARCH-003 §3). The rows carry the full I3 match state —
-- reasons, the referencing decision rule and the auto_* override
-- preservation — so the matching engine can compare a freshly computed
-- outcome against what is stored for the pair and the reference-matrix
-- tests can assert per-pair state (ARCH-003 §8a). Ordering is by rule
-- version, then creation time and id, newest first, for a stable read.
-- name: ListMatchesByVulnerabilityComponent :many
SELECT id, vulnerability_id, component_id, method, score, confidence, rule_version, created_at,
       reasons, decision_rule_id, auto_method, auto_confidence, auto_score
FROM matches
WHERE vulnerability_id = @vulnerability_id AND component_id = @component_id
ORDER BY rule_version DESC, created_at DESC, id;
