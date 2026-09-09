-- matches write (ARCH-001 §1, ADR-015, WP-1b.02).
--
-- Method-led match: method authoritative, confidence and score derived from
-- it through the versioned ADR-015 mapping.

-- InsertMatch records a method-led match and returns its id — the newly
-- inserted one, or the already existing one when (vulnerability_id,
-- component_id, rule_version) is present. Re-running the source inserts
-- nothing twice (ARCH-001 §3 step 4), and a healing run still learns the id
-- of an earlier match. created_at comes from the injected clock.
-- name: InsertMatch :one
WITH inserted AS (
    INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
    VALUES (@vulnerability_id, @component_id, @method, @score, @confidence, @rule_version, @created_at)
    ON CONFLICT (vulnerability_id, component_id, rule_version) DO NOTHING
    RETURNING id
)
SELECT id FROM inserted
UNION ALL
SELECT id FROM matches
WHERE vulnerability_id = @vulnerability_id AND component_id = @component_id AND rule_version = @rule_version
LIMIT 1;
