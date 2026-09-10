package export

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Artifact is the stored reference of one materialised export artifact
// (ARCH-007 §1.2): the spool-relative path, the byte size and the SHA-256
// checksum recorded in the exports row (storage_path / size_bytes /
// checksum). The artifact bytes themselves live in the server-local export
// spool, never in the database — exports are large, time-limited
// business-content copies that self-expire and must stay out of the
// audit/backup retention path.
type Artifact struct {
	// Path is the spool-relative path of the artifact (relative to
	// export.dir), never absolute: the exports row stores this reference and
	// a download resolves it against the configured spool root.
	Path string
	// SizeBytes is the byte size of the materialised artifact.
	SizeBytes int64
	// Checksum is the lowercase hex SHA-256 of the artifact bytes.
	Checksum string
}

// Spool is the server-local export artifact store (ARCH-007 §1.2): a base
// directory (the configured export.dir) under which artifacts are written by
// key and read back by their spool-relative path. It is the filesystem half
// of the export pipeline — the export.generate job writes an artifact and
// hands the reference to the exports row; a download streams the stored file
// back. It owns no business logic and no format knowledge: callers pass the
// already-materialised bytes.
//
// The store is deliberately path-safe: every key and path is resolved
// relative to the spool root and an absolute path or one that escapes the
// root (a ".." segment) is rejected, so a stored reference can never read or
// write outside export.dir.
type Spool struct {
	dir string
}

// NewSpool returns a spool rooted at dir (the export.dir config value). An
// empty dir is rejected at the first use (Write/Open) rather than here, so a
// Service can be assembled before the configuration is available.
func NewSpool(dir string) *Spool { return &Spool{dir: dir} }

// Dir returns the configured spool root.
func (s *Spool) Dir() string { return s.dir }

// ArtifactKey is the canonical spool key of one export artifact (ARCH-007
// §1.2): the export id plus its format extension, e.g. the value the
// export.generate job hands to Write. It is a convenience for the caller —
// the spool accepts any safe relative key.
func ArtifactKey(exportID string, format Format) string {
	return exportID + "." + string(format)
}

// Write stores the bytes read from r under key inside the spool and returns
// the stored reference with its size and SHA-256 checksum (ARCH-007 §1.2).
// The write is atomic: the bytes stream into a sibling temp file (checksummed
// on the fly) which is renamed over the target, so a crash never leaves a
// half-written artifact that a download could serve as complete. The
// directory hierarchy of key is created as needed (0o750).
func (s *Spool) Write(_ context.Context, key string, r io.Reader) (Artifact, error) {
	name, err := s.clean(key)
	if err != nil {
		return Artifact{}, err
	}
	abs := filepath.Join(s.dir, name)
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return Artifact{}, fmt.Errorf("export: create spool directory: %w", err)
	}
	tmp, err := os.CreateTemp(parent, "."+filepath.Base(abs)+".tmp-*")
	if err != nil {
		return Artifact{}, fmt.Errorf("export: create spool temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), r)
	if err != nil {
		_ = tmp.Close()
		cleanup()
		return Artifact{}, fmt.Errorf("export: write spool artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return Artifact{}, fmt.Errorf("export: close spool artifact: %w", err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		cleanup()
		return Artifact{}, fmt.Errorf("export: store spool artifact: %w", err)
	}
	return Artifact{
		Path:      name,
		SizeBytes: n,
		Checksum:  hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

// Open returns a reader over the stored artifact at the spool-relative path
// (the exports.storage_path reference). A path that is absolute or escapes
// the spool root is rejected before any file is touched.
func (s *Spool) Open(_ context.Context, path string) (io.ReadCloser, error) {
	abs, err := s.resolve(path)
	if err != nil {
		return nil, err
	}
	// G304 (file inclusion via variable): the path is validated by resolve
	// to stay inside the configured spool root (absolute paths and ".."
	// escapes are rejected), so this is a scoped allow for this call site.
	f, err := os.Open(abs) //nolint:gosec // G304: path validated relative to the spool root
	if err != nil {
		return nil, fmt.Errorf("export: open spool artifact: %w", err)
	}
	return f, nil
}

// Remove deletes the stored artifact at the spool-relative path (the
// exports.storage_path reference) — the daily sweep's deletion of an expired
// export artifact (ARCH-007 §1.2). A missing artifact is not an error: the
// sweep only wants the file gone, and an already-deleted (or never written)
// artifact already satisfies that. A path that is absolute or escapes the
// spool root is rejected before any file is touched.
func (s *Spool) Remove(_ context.Context, path string) error {
	abs, err := s.resolve(path)
	if err != nil {
		return err
	}
	if err := os.Remove(abs); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("export: remove spool artifact: %w", err)
	}
	return nil
}

// clean validates a spool-relative key/path and returns it in canonical form.
func (s *Spool) clean(rel string) (string, error) {
	if strings.TrimSpace(s.dir) == "" {
		return "", fmt.Errorf("export: spool directory is not configured")
	}
	if strings.TrimSpace(rel) == "" {
		return "", fmt.Errorf("export: empty artifact path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("export: artifact path %q must be relative", rel)
	}
	name := filepath.Clean(rel)
	if name == "." || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("export: artifact path %q escapes the spool", rel)
	}
	return name, nil
}

// resolve validates a spool-relative path and returns its absolute location.
func (s *Spool) resolve(rel string) (string, error) {
	name, err := s.clean(rel)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, name), nil
}
