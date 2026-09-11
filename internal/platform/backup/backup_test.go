package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// TestResolveIdentity proves the runtime-injected identity is resolved from
// the referenced secret and that every failure references the key only.
func TestResolveIdentity(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	t.Setenv("RS_TEST_IDENTITY", identity.String())

	got, err := ResolveIdentity("RS_TEST_IDENTITY")
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if got.Recipient().String() != identity.Recipient().String() {
		t.Fatalf("resolved a different identity")
	}

	if _, err := ResolveIdentity(""); err == nil {
		t.Fatal("empty reference: want error")
	}
	if _, err := ResolveIdentity("RS_TEST_UNSET_IDENTITY_XYZ"); err == nil {
		t.Fatal("unset secret: want error")
	}
	t.Setenv("RS_TEST_BAD_IDENTITY", "not-an-age-identity")
	if _, err := ResolveIdentity("RS_TEST_BAD_IDENTITY"); err == nil {
		t.Fatal("invalid secret: want error")
	} else if strings.Contains(err.Error(), "not-an-age-identity") {
		t.Fatalf("error leaked the secret value: %v", err)
	}
}

// TestDatabaseURLWithName preserves the credentials/query and swaps the db.
func TestDatabaseURLWithName(t *testing.T) {
	got, err := DatabaseURLWithName("postgres://u:p@h:5432/db?sslmode=disable", "other")
	if err != nil {
		t.Fatalf("DatabaseURLWithName: %v", err)
	}
	if got != "postgres://u:p@h:5432/other?sslmode=disable" {
		t.Fatalf("got %q", got)
	}
	if _, err := DatabaseURLWithName("not-a-url", "x"); err == nil {
		t.Fatal("invalid url: want error")
	}
}

// TestTempDatabaseNameIsSafe proves the throwaway name passes the CREATE/DROP
// guard.
func TestTempDatabaseNameIsSafe(t *testing.T) {
	name := TempDatabaseName(time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC))
	if !dbNameMask.MatchString(name) {
		t.Fatalf("temp database name %q is not allowed by the guard", name)
	}
}

// TestSettingsPGToolDefaults proves the pg tool fallbacks.
func TestSettingsPGToolDefaults(t *testing.T) {
	var s Settings
	if s.pgDump() != "pg_dump" || s.pgRestore() != "pg_restore" {
		t.Fatalf("defaults = %q/%q", s.pgDump(), s.pgRestore())
	}
	s.PGDump = "docker compose exec -T db pg_dump"
	if s.pgDump() != "docker compose exec -T db pg_dump" {
		t.Fatalf("override not honoured: %q", s.pgDump())
	}
}

// TestDecryptRoundTrip proves the age encrypt/decrypt plumbing without a
// database: an artifact encrypted to the identity decrypts back to the
// plaintext, and a foreign identity fails.
func TestDecryptRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	plaintext := []byte("PGDMP-fake-custom-format-dump")

	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, identity.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "artifact.dump.age")
	dst := filepath.Join(dir, "dump.pgcustom")
	if err := os.WriteFile(src, sealed.Bytes(), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if err := Decrypt(src, dst, identity); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	got, err := os.ReadFile(dst) // #nosec G304 -- dst is the temp file the test just decrypted into.
	if err != nil {
		t.Fatalf("read dump: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted %q, want %q", got, plaintext)
	}

	other, _ := age.GenerateX25519Identity()
	if err := Decrypt(src, filepath.Join(dir, "nope"), other); err == nil {
		t.Fatal("decrypt with a foreign identity: want error")
	}
}

// TestPruneAndLatest proves the retention window and newest-artifact selection.
func TestPruneAndLatest(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	write := func(name string, mod time.Time) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
		return p
	}
	old := write("risksignal-20200101T000000Z.dump.age", now.Add(-20*24*time.Hour))
	recent := write("risksignal-20260910T120000Z.dump.age", now.Add(-24*time.Hour))
	write("notes.txt", now.Add(-40*24*time.Hour)) // not an artifact: ignored

	latest, err := Latest(dir)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if latest != recent {
		t.Fatalf("Latest = %q, want %q", latest, recent)
	}

	removed, err := Prune(dir, 14, now)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(removed) != 1 || removed[0] != old {
		t.Fatalf("Prune removed %v, want [%s]", removed, old)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old artifact still present")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatalf("recent artifact gone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("Prune removed a non-artifact file: %v", err)
	}

	if _, err := Latest(t.TempDir()); err == nil {
		t.Fatal("Latest on an empty dir: want error")
	}
}
