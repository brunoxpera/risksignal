package credstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// testTime is the fixed instant of the store tests.
var testTime = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

func TestFileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "credentials.json")
	s := OpenPath(path)

	// A missing store is an empty store, not an error.
	if _, ok, err := s.Load("https://idp.example"); err != nil || ok {
		t.Fatalf("Load on empty store = (%v, %v), want (zero, false, nil)", ok, err)
	}
	if issuers, err := s.Issuers(); err != nil || len(issuers) != 0 {
		t.Fatalf("Issuers on empty store = (%v, %v), want empty", issuers, err)
	}

	cred := Credential{
		Issuer:       "https://idp.example",
		SubjectID:    "https://idp.example::sub-1",
		DisplayName:  "Ada Lovelace",
		Email:        "ada@example.com",
		AccessToken:  "at-secret",
		RefreshToken: "rt-secret",
		IDToken:      "id-secret",
		TokenType:    "Bearer",
		ExpiresAt:    testTime.Add(time.Hour),
		ObtainedAt:   testTime,
	}
	if err := s.Save(cred); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := s.Load("https://idp.example")
	if err != nil || !ok {
		t.Fatalf("Load = (ok %v, err %v), want present", ok, err)
	}
	if got != cred {
		t.Fatalf("Load = %+v, want %+v", got, cred)
	}

	// A second issuer is stored alongside the first and Issuers is sorted.
	if err := s.Save(Credential{Issuer: "https://other.example", AccessToken: "x"}); err != nil {
		t.Fatalf("Save second: %v", err)
	}
	issuers, err := s.Issuers()
	if err != nil {
		t.Fatalf("Issuers: %v", err)
	}
	if len(issuers) != 2 || issuers[0] != "https://idp.example" || issuers[1] != "https://other.example" {
		t.Fatalf("Issuers = %v, want sorted [idp, other]", issuers)
	}

	// Delete is idempotent and reports presence.
	if removed, err := s.Delete("https://idp.example"); err != nil || !removed {
		t.Fatalf("Delete = (%v, %v), want (true, nil)", removed, err)
	}
	if removed, err := s.Delete("https://idp.example"); err != nil || removed {
		t.Fatalf("second Delete = (%v, %v), want (false, nil)", removed, err)
	}
	if _, ok, _ := s.Load("https://idp.example"); ok {
		t.Fatal("credential survived Delete")
	}
}

func TestFileStoreOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
	// The store's parent directory does not exist yet, so Save must create it
	// on demand; assert the mode it creates it with rather than relying on
	// t.TempDir(), whose mode is umask-dependent.
	path := filepath.Join(t.TempDir(), "nested", "credentials.json")
	s := OpenPath(path)
	if err := s.Save(Credential{Issuer: "https://idp.example", AccessToken: "at"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("store permissions = %o, want 0600", perm)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	// The store creates its parent directory 0700 (umask-independent); it
	// must not leave any group/other access.
	if perm := dirInfo.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("store directory permissions = %o, want no group/other access", perm)
	}
}

func TestFileStoreRejectsEmptyIssuerAndBadSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	s := OpenPath(path)
	if err := s.Save(Credential{AccessToken: "at"}); err == nil {
		t.Fatal("Save with an empty issuer succeeded, want error")
	}

	// An unsupported schema version fails closed.
	if err := os.WriteFile(path, []byte(`{"schema_version":99,"credentials":{}}`), 0o600); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	if _, _, err := s.Load("https://idp.example"); err == nil {
		t.Fatal("Load of an unsupported schema version succeeded, want error")
	}
}

func TestFileStoreDocumentShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	s := OpenPath(path)
	if err := s.Save(Credential{Issuer: "https://idp.example", AccessToken: "at"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// #nosec G304 — path is this test's own temp file (filepath.Join of the
	// t.TempDir() constant), never external input.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("stored document is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != schemaVersion {
		t.Fatalf("schema_version = %d, want %d", doc.SchemaVersion, schemaVersion)
	}
	if _, ok := doc.Credentials["https://idp.example"]; !ok {
		t.Fatalf("stored document lacks the credential: %s", data)
	}
}

func TestCredentialExpired(t *testing.T) {
	cases := []struct {
		name string
		cred Credential
		now  time.Time
		want bool
	}{
		{"no stated expiry", Credential{}, testTime, false},
		{"future expiry", Credential{ExpiresAt: testTime.Add(time.Minute)}, testTime, false},
		{"past expiry", Credential{ExpiresAt: testTime.Add(-time.Minute)}, testTime, true},
		{"exactly at expiry", Credential{ExpiresAt: testTime}, testTime, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cred.Expired(tc.now); got != tc.want {
				t.Fatalf("Expired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultPathHonoursOverride(t *testing.T) {
	t.Setenv(EnvFile, "/tmp/explicit-credentials.json")
	got, err := defaultPath()
	if err != nil {
		t.Fatalf("defaultPath: %v", err)
	}
	if got != "/tmp/explicit-credentials.json" {
		t.Fatalf("defaultPath = %q, want the override", got)
	}
}
