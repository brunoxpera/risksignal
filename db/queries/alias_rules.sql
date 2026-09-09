-- alias_rules: the versioned, auditable alias configuration statements
-- (ARCH-003 §1.4, ch. 7.1, ADR-015, WP-3.03a / DEV-056). Alias rules are
-- controlled vendor/product aliases resolved at match time through the
-- symmetric one-hop alias closure — never at write time (ARCH-003 §2);
-- from_value/to_value are already NFKC + trim + lowercase at the boundary.
--
-- Versioning: version is the monotonic ruleset version counter — every
-- rule change (create, disable, enable, remap) belongs to the current
-- ruleset version, which the caller reads through
-- GetLatestAliasRulesVersion and bumps before writing (the composite
-- effective rule version is RulesetVersion(alias, decision),
-- internal/domain/mapping.go: "a<alias.version>d<decision.version>",
-- flowing into matches.rule_version and the matching.rebuild dedupe key).
-- History is preserved by UQ (scope, from_value, version): an earlier row
-- of the same alias stays readable at its own version. Rows are audited
-- config — disabled rules are inert, never deleted (schema comment), so
-- the update surface is the enabled toggle; the matching engine's
-- effective-set reads (enabled closure inputs) land with WP-3.06.

-- InsertAliasRule creates one alias rule row and returns its id.
-- created_at/updated_at come from the injected clock; enabled defaults to
-- true at the schema level — the caller passes the explicit value so the
-- write is a full statement of the rule's state.
-- name: InsertAliasRule :one
INSERT INTO alias_rules (scope, from_value, to_value, version, enabled, reason, created_at, updated_at)
VALUES (@scope, @from_value, @to_value, @version, @enabled, @reason, @created_at, @updated_at)
RETURNING id;

-- SetAliasRuleEnabled toggles one alias rule between active and inert
-- (domain.AliasRule.Disable/Enable; disabled rules stay readable and
-- versioned, they are never deleted). updated_at comes from the injected
-- clock. The returned row count is 0 for an unknown id; the caller
-- supplies the ruleset version bump separately (a ruleset change is
-- versioned, this statement only flips the state of one row).
-- name: SetAliasRuleEnabled :execrows
UPDATE alias_rules
SET enabled    = @enabled,
    updated_at = @updated_at
WHERE id = @id;

-- ListAliasRules returns the full alias rule history — the management/
-- audit read (newest ruleset version first, then scope and from_value for
-- a stable order). The matching engine does not consume this read: it
-- resolves the alias closure over the effective, enabled rules of the
-- current version (WP-3.06).
-- name: ListAliasRules :many
SELECT id, scope, from_value, to_value, version, enabled, reason, created_at, updated_at
FROM alias_rules
ORDER BY version DESC, scope, from_value;

-- GetLatestAliasRulesVersion returns the current alias ruleset version
-- counter — the monotonic max(version) of the table, 0 when no alias rule
-- exists yet. It is one half of the composite effective rule version the
-- matching use case derives through domain.RulesetVersion
-- ("a<alias.version>d<decision.version>", ARCH-003 §3) and stamps on every
-- match row; a change to this table bumps the composite and enqueues a
-- fresh matching.rebuild.
-- name: GetLatestAliasRulesVersion :one
SELECT COALESCE(max(version), 0)::integer AS version
FROM alias_rules;
