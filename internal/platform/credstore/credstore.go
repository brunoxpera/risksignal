// Package credstore is the CLI credential store of the human login
// (ARCH-005 §2, ARCH-006 §5, concept ch. 11.3/12.1): the OS-user-scoped,
// permission-restricted place the CLI keeps the OIDC tokens it obtained
// through the device authorization flow (or the loopback callback login).
//
// Tokens are held per issuer and are never logged: the CLI renders only the
// non-secret identity of the login (issuer, subject, display name, expiry) —
// the access/refresh tokens never reach stdout, stderr or a log line
// (NFR-006/NFR-014). The adapter (`internal/adapters/oidc`) returns the raw
// token set to the login plumbing only; this package persists it.
//
// # Storage
//
// The default backend is a single JSON document under the OS user
// configuration directory (macOS: ~/Library/Application Support; Linux:
// $XDG_CONFIG_HOME or ~/.config), created with the owner-only modes
// 0700 (directory) / 0600 (file). It is the OS-user-scoped credential store:
// the file is readable only by the login's owner, exactly like the protected
// key store of the platform, without a cgo/keychain dependency. The
// RISKSIGNAL_CREDENTIAL_FILE override selects an explicit path (tests and
// CI); an OS keychain backend can implement Store without touching the CLI.
//
// # Non-interactive
//
// The store is only ever read/written by the CLI's auth subcommands; opening
// a missing store is not an error (an explicit "not logged in" verdict), and
// saving creates the parent directory on demand. No command prompts.
package credstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EnvFile is the environment variable that overrides the credential-store
// path (an explicit file, not a directory). It exists for tests and CI and
// keeps the CLI non-interactive in every environment.
const EnvFile = "RISKSIGNAL_CREDENTIAL_FILE"

// schemaVersion versions the stored document. Bump only when a stored
// credential's keys change incompatibly; an unknown version fails closed
// (the operator re-logs in) rather than guessing.
const schemaVersion = 1

// Credential is one stored login per issuer (ARCH-005 §2). The token fields
// are the secrets: they are persisted with owner-only permissions and are
// never rendered. ExpiresAt/ObtainedAt are set from the OIDC token response
// (expires_in against the injected clock); a zero ExpiresAt means the
// provider stated no expiry.
type Credential struct {
	// Issuer is the OIDC issuer the credential belongs to (the store key).
	Issuer string `json:"issuer"`
	// SubjectID is the issuer-qualified external subject ("<issuer>::<sub>").
	SubjectID string `json:"subject_id"`
	// DisplayName is the verified display name (may be empty).
	DisplayName string `json:"display_name,omitempty"`
	// Email is the verified e-mail (may be empty).
	Email string `json:"email,omitempty"`
	// AccessToken/RefreshToken/IDToken are the raw tokens — secrets.
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	// TokenType is the OAuth token type (e.g. "Bearer"), may be empty.
	TokenType string `json:"token_type,omitempty"`
	// ExpiresAt is the access-token expiry; zero means "not stated".
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// ObtainedAt is the instant the login completed (the injected clock).
	ObtainedAt time.Time `json:"obtained_at"`
}

// Expired reports whether the credential's access token is past its stated
// expiry at the given instant. A zero ExpiresAt is "not stated" and never
// reports expired (the CLI cannot invent an expiry).
func (c Credential) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

// Store is the credential-store seam of the CLI (ARCH-006 §5). The default
// backend is *FileStore; an OS keychain backend may implement it without
// changing the auth subcommands. Load never errors on a missing entry (the
// bool reports presence), so an explicit "not logged in" verdict needs no
// error handling; Delete is idempotent.
type Store interface {
	// Load returns the stored credential for issuer, or ok=false when none
	// is stored.
	Load(issuer string) (Credential, bool, error)
	// Save writes the credential (creating the store on demand), replacing a
	// previous credential of the same issuer.
	Save(c Credential) error
	// Delete removes the credential of issuer and reports whether one
	// existed. A missing entry is not an error.
	Delete(issuer string) (bool, error)
	// Issuers returns the issuers with a stored credential, sorted.
	Issuers() ([]string, error)
}

// FileStore is the default Store: one owner-only JSON document.
type FileStore struct {
	path string
}

// Open opens the default, OS-user-scoped credential store. The path is the
// RISKSIGNAL_CREDENTIAL_FILE override when set, else the per-user
// configuration directory of the platform.
func Open() (*FileStore, error) {
	path, err := defaultPath()
	if err != nil {
		return nil, err
	}
	return &FileStore{path: path}, nil
}

// OpenPath opens a credential store at an explicit path (tests).
func OpenPath(path string) *FileStore { return &FileStore{path: path} }

// Path returns the file the store reads and writes (diagnostics; never a
// secret).
func (s *FileStore) Path() string { return s.path }

// document is the stored JSON shape: a schema version and the credentials by
// issuer.
type document struct {
	SchemaVersion int                   `json:"schema_version"`
	Credentials   map[string]Credential `json:"credentials"`
}

// Load returns the stored credential for issuer.
func (s *FileStore) Load(issuer string) (Credential, bool, error) {
	doc, err := s.read()
	if err != nil {
		return Credential{}, false, err
	}
	c, ok := doc.Credentials[issuer]
	return c, ok, nil
}

// Save writes the credential, replacing a previous one of the same issuer.
func (s *FileStore) Save(c Credential) error {
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("credstore: credential issuer must not be empty")
	}
	doc, err := s.read()
	if err != nil {
		return err
	}
	doc.Credentials[c.Issuer] = c
	return s.write(doc)
}

// Delete removes the credential of issuer.
func (s *FileStore) Delete(issuer string) (bool, error) {
	doc, err := s.read()
	if err != nil {
		return false, err
	}
	if _, ok := doc.Credentials[issuer]; !ok {
		return false, nil
	}
	delete(doc.Credentials, issuer)
	return true, s.write(doc)
}

// Issuers returns the issuers with a stored credential, sorted.
func (s *FileStore) Issuers() ([]string, error) {
	doc, err := s.read()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Credentials))
	for issuer := range doc.Credentials {
		out = append(out, issuer)
	}
	sort.Strings(out)
	return out, nil
}

// read loads the stored document; a missing file is an empty document (not
// an error), so an unlogged CLI reports "not logged in" without a failure.
func (s *FileStore) read() (document, error) {
	empty := func() document { return document{SchemaVersion: schemaVersion, Credentials: map[string]Credential{}} }

	// G304 (file inclusion via variable): path is the CLI's own credential
	// store (the RISKSIGNAL_CREDENTIAL_FILE override or the OS user config
	// directory), never request-controlled input. This is a scoped allow for
	// this call site, not a blanket G304 exclusion.
	data, err := os.ReadFile(s.path) //nolint:gosec // G304: operator/user-scoped store path, not user-controlled input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return empty(), nil
		}
		return document{}, fmt.Errorf("credstore: read store: %w", err)
	}
	if len(data) == 0 {
		return empty(), nil
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return document{}, fmt.Errorf("credstore: parse store: %w", err)
	}
	if doc.SchemaVersion != schemaVersion {
		return document{}, fmt.Errorf("credstore: unsupported store schema version %d", doc.SchemaVersion)
	}
	if doc.Credentials == nil {
		doc.Credentials = map[string]Credential{}
	}
	return doc, nil
}

// write persists the document atomically with owner-only permissions: the
// parent directory is created 0700, the file is written to a sibling temp
// file 0600 and renamed over the target, so a crash never leaves a partial
// store and the tokens are never world-readable.
func (s *FileStore) write(doc document) error {
	doc.SchemaVersion = schemaVersion
	if doc.Credentials == nil {
		doc.Credentials = map[string]Credential{}
	}
	data, err := json.MarshalIndent(&doc, "", "  ")
	if err != nil {
		return fmt.Errorf("credstore: encode store: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("credstore: create store directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("credstore: create temp store: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("credstore: restrict temp store: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("credstore: write store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("credstore: write store: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("credstore: replace store: %w", err)
	}
	return nil
}

// defaultPath resolves the credential-store path: the explicit
// RISKSIGNAL_CREDENTIAL_FILE override when set, else the per-user
// configuration directory.
func defaultPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv(EnvFile)); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("credstore: resolve user config directory: %w", err)
	}
	return filepath.Join(dir, "risksignal", "credentials.json"), nil
}
