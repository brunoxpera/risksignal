package repo

// I6 exit-criteria consolidation (ARCH-007 §2.3/§7 control 3/§12, WP-6.12 /
// DEV-134): the I6 persistence, audit-integrity and role proofs of the
// postgres adapter as `I6ExitCriteria`-named gates. Each subtest delegates to
// the landed proof (WP-6.02/6.10 / DEV-112/123 and the retention-role
// amendment) — the SQL and the role grants are not re-implemented.

import "testing"

// TestI6ExitCriteriaAuditIntegrity is the ARCH-007 §7 control-3 acceptance
// case: the optional hash chain stamps and verifies an untampered trail and
// fails (naming the row) after an injected edit, the chain gate leaves rows
// unchained when disabled, and the application role is denied UPDATE/DELETE on
// audit_events.
func TestI6ExitCriteriaAuditIntegrity(t *testing.T) {
	t.Run("chain stamps and verifies, tampering fails", func(t *testing.T) {
		TestAuditHashChainStampsAndVerifies(t)
	})
	t.Run("chain gate off leaves rows unchained", func(t *testing.T) {
		TestAuditHashChainDisabledLeavesRowsUnchained(t)
	})
	t.Run("app role is denied update/delete on audit_events", func(t *testing.T) {
		TestAuditAppendOnlyRoleDeniesUpdateDelete(t)
	})
}

// TestI6ExitCriteriaRetentionPersistence is the AT-021/NFR-015 persistence
// case: the I6 operations schema and queries (exports, retention runs, legal
// holds, the candidate scan) round-trip on a real PostgreSQL, and the
// dedicated retention role runs retention + pseudonymisation end-to-end while
// the runtime role stays append-only.
func TestI6ExitCriteriaRetentionPersistence(t *testing.T) {
	t.Run("operations schema and queries", func(t *testing.T) {
		TestI6PersistenceIntegration(t)
	})
	t.Run("retention repository lifecycle", func(t *testing.T) {
		TestRetentionRepoIntegration(t)
	})
	t.Run("retention role grants are least-privilege", func(t *testing.T) {
		TestRetentionRoleLeastPrivilegeGrants(t)
	})
	t.Run("retention role runs retention and pseudonymisation", func(t *testing.T) {
		TestRetentionRoleRunsRetentionAndPseudonymisationEndToEnd(t)
	})
	t.Run("runtime role grants are least-privilege", func(t *testing.T) {
		TestRuntimeRoleLeastPrivilegeGrants(t)
	})
	t.Run("runtime role boots and audit stays append-only", func(t *testing.T) {
		TestRuntimeRoleBootsDomainAndAuditStaysAppendOnly(t)
	})
}
