package main

// Non-database unit tests of the backup/restore-test CLI surfaces (WP-6.09 /
// DEV-122): the encryption-key reference is mandatory at command time and the
// error references the key only, and a missing artifact fails cleanly.

import (
	"strings"
	"testing"

	"filippo.io/age"
)

// TestBackupRequiresEncryptionKeyReference proves the backup command fails as
// a validation error (exit 2) when backup.encryption_key_ref is unset, and the
// message references the key only.
func TestBackupRequiresEncryptionKeyReference(t *testing.T) {
	env := cliValidEnv() // no RISKSIGNAL_BACKUP_ENCRYPTION_KEY_REF
	code, stdout, _ := runCLI(t, env, "diagnose", "backup", "--output", "json")
	if code != exitValidation {
		t.Fatalf("exit = %d, want %d", code, exitValidation)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Error == nil || envJSON.Error.Class != classValidation {
		t.Fatalf("error = %+v, want a validation error", envJSON.Error)
	}
	if !strings.Contains(envJSON.Error.Message, "backup.encryption_key_ref") {
		t.Fatalf("message %q does not reference the key", envJSON.Error.Message)
	}
}

// TestRestoreTestWithoutArtifactFailsCleanly proves restore-test reports the
// missing artifact without a database round-trip.
func TestRestoreTestWithoutArtifactFailsCleanly(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	env := cliValidEnv()
	env["RISKSIGNAL_BACKUP_DIR"] = t.TempDir()
	env["RISKSIGNAL_BACKUP_ENCRYPTION_KEY_REF"] = "RISKSIGNAL_BACKUP_TEST_IDENTITY"
	env["RISKSIGNAL_BACKUP_TEST_IDENTITY"] = identity.String()
	code, stdout, _ := runCLI(t, env, "diagnose", "restore-test", "--output", "json")
	if code != exitGeneric {
		t.Fatalf("exit = %d, want %d", code, exitGeneric)
	}
	envJSON := decodeEnvelope(t, stdout)
	if envJSON.Error == nil || !strings.Contains(envJSON.Error.Message, "no encrypted backup") {
		t.Fatalf("error = %+v, want a missing-artifact message", envJSON.Error)
	}
}

// TestBackupHelp prints usage and exits 0 without a database.
func TestBackupHelp(t *testing.T) {
	code, _, _ := runCLI(t, cliValidEnv(), "diagnose", "backup", "--help")
	if code != exitOK {
		t.Fatalf("help exit = %d, want 0", code)
	}
}
