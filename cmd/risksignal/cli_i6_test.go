package main

// CLI validation-path tests of the I6 commands (WP-6.07 / DEV-119): the
// argument validation the commands enforce before any database work, the
// destructive-confirmation rules (--yes / --commit) and the non-interactive
// discipline. They run without a database (the validated commands fail at the
// argument check, before the composition root opens a pool).

import (
	"strings"
	"testing"
)

func TestExportCreateRequiresFormat(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "export", "create")
	assertValidationFailure(t, code, stdout, stderr, "--format is mandatory")
}

func TestExportCreateRejectsInvalidFormat(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "export", "create", "--format", "xml")
	assertValidationFailure(t, code, stdout, stderr, "must be")
}

func TestExportCreateRejectsInvalidPriority(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "export", "create", "--format", "csv", "--priority", "P9")
	assertValidationFailure(t, code, stdout, stderr, "invalid --priority")
}

func TestExportCreateRejectsInvalidTimestamp(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "export", "create", "--format", "csv", "--created-from", "yesterday")
	assertValidationFailure(t, code, stdout, stderr, "RFC 3339")
}

func TestExportDownloadRequiresTargets(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "export", "download")
	assertValidationFailure(t, code, stdout, stderr, "--export is mandatory")

	code, stdout, stderr = runCLI(t, cliValidEnv(), "export", "download", "--export", "exp-1")
	assertValidationFailure(t, code, stdout, stderr, "--out is mandatory")
}

func TestExportUnknownSubcommand(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "export", "delete")
	assertValidationFailure(t, code, stdout, stderr, "unknown subcommand")
}

func TestRetentionRequiresExactlyOneMode(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "maintenance", "retention")
	assertValidationFailure(t, code, stdout, stderr, "exactly one of")

	code, stdout, stderr = runCLI(t, cliValidEnv(), "maintenance", "retention", "--dry-run", "--list")
	assertValidationFailure(t, code, stdout, stderr, "exactly one of")
}

func TestRetentionApproveRequiresReasonAndConfirmation(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "maintenance", "retention", "--approve", "run-1")
	assertValidationFailure(t, code, stdout, stderr, "--reason is mandatory")

	code, stdout, stderr = runCLI(t, cliValidEnv(), "maintenance", "retention", "--approve", "run-1", "--reason", "reviewed")
	assertValidationFailure(t, code, stdout, stderr, "pass --yes")
}

func TestIdentityPseudonymizeRequiresUser(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "maintenance", "identity-pseudonymize")
	assertValidationFailure(t, code, stdout, stderr, "--user is mandatory")
}

func TestIdentityPseudonymizeCommitRequiresReason(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "maintenance", "identity-pseudonymize", "--user", "u-1", "--commit")
	assertValidationFailure(t, code, stdout, stderr, "--reason is mandatory")
}

func TestLegalHoldCreateRequiresAggregateAndReason(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "legal-hold", "create")
	assertValidationFailure(t, code, stdout, stderr, "--aggregate is mandatory")

	code, stdout, stderr = runCLI(t, cliValidEnv(), "legal-hold", "create", "--aggregate", "sig-1")
	assertValidationFailure(t, code, stdout, stderr, "--reason is mandatory")
}

func TestLegalHoldReleaseRequiresConfirmation(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "legal-hold", "release", "--hold", "hold-1", "--reason", "done")
	assertValidationFailure(t, code, stdout, stderr, "pass --yes")
}

func TestLegalHoldUnknownSubcommand(t *testing.T) {
	code, stdout, stderr := runCLI(t, cliValidEnv(), "legal-hold", "delete")
	assertValidationFailure(t, code, stdout, stderr, "unknown subcommand")
}

// TestUsageDocumentsI6Commands: the top-level help lists the new I6 surfaces
// (they are discoverable and documented, ch. 11.3).
func TestUsageDocumentsI6Commands(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil, "help")
	if code != exitOK {
		t.Fatalf("help exit code = %d, want 0 (stderr %s)", code, stderr)
	}
	for _, want := range []string{"export create", "export download", "maintenance retention", "maintenance identity-pseudonymize", "legal-hold create", "legal-hold release", "legal-hold list"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("usage does not mention %q", want)
		}
	}
}
