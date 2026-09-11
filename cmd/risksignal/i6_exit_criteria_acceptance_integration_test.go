package main

// I6 exit-criteria consolidation (ARCH-007 §1.1/§7 control 3b/§12, WP-6.12 /
// DEV-134): the composition-root acceptance proofs at cmd/risksignal — the
// backup/restore restore-test (AT-015/NFR-011), the tampered-audit-chain CLI
// verifier (§12 fault injection (c)) and the export/retention channel parity
// (NFR-013) — as `I6ExitCriteria`-named gates. Each subtest delegates to the
// landed proof (WP-6.07/6.09/6.10); the proofs are not re-implemented.

import "testing"

// TestI6ExitCriteriaBackupRestore is the AT-015/NFR-011 acceptance case: the
// encrypted off-host backup restores into a throwaway empty instance and
// reproduces the schema, objects, sample hashes, open signals and the audit
// chain, recording the backup.restored event.
func TestI6ExitCriteriaBackupRestore(t *testing.T) {
	t.Run("restore reproduces schema, objects and audit", func(t *testing.T) {
		TestRestoreTestReproducesSchemaObjectsAndAudit(t)
	})
}

// TestI6ExitCriteriaTamperedAuditChain is the ARCH-007 §12 fault injection (c):
// the `diagnose audit-chain` verifier reports an intact trail with exit 0 and
// fails with the conflict exit code after an injected row edit.
func TestI6ExitCriteriaTamperedAuditChain(t *testing.T) {
	t.Run("diagnose audit-chain passes intact and fails tampered", func(t *testing.T) {
		TestCLIDiagnoseAuditChain(t)
	})
}

// TestI6ExitCriteriaChannelParity is the NFR-013 acceptance case for the I6
// surfaces: the export creation and the retention dry-run freeze the same
// filter/format and store the same counts-only report through the HTTP API and
// the CLI channels.
func TestI6ExitCriteriaChannelParity(t *testing.T) {
	t.Run("export channel parity", func(t *testing.T) {
		TestI6ExportChannelParity(t)
	})
	t.Run("retention channel parity", func(t *testing.T) {
		TestI6RetentionChannelParity(t)
	})
}
