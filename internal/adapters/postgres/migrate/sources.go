package migrate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// source is one embedded migration file.
type source struct {
	Version int64
	Path    string
}

// parseVersion extracts the migration version from a file name, mirroring
// goose's rule for SQL migrations: the number before the first underscore
// (NumericComponent). Keeping both parsers in agreement matters because the
// checksum log is keyed by version.
func parseVersion(name string) (int64, error) {
	before, _, ok := strings.Cut(path.Base(name), "_")
	if !ok {
		return 0, fmt.Errorf("migration file %q has no version prefix (expected <number>_<name>.sql)", name)
	}
	n, err := strconv.ParseInt(before, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("migration file %q: invalid version prefix %q", name, before)
	}
	if n < 1 {
		return 0, fmt.Errorf("migration file %q: version must be greater than zero", name)
	}
	return n, nil
}

// listSources enumerates the embedded *.sql migration files in version order.
// Files goose would reject (unparseable names, duplicate versions) are
// rejected here too, so the checksum layer and goose can never disagree about
// the migration set.
func listSources(fsys fs.FS) ([]source, error) {
	files, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, err
	}
	byVersion := make(map[int64]source, len(files))
	for _, name := range files {
		v, err := parseVersion(name)
		if err != nil {
			return nil, err
		}
		if _, dup := byVersion[v]; dup {
			return nil, fmt.Errorf("duplicate migration version %d (files %q and %q)", v, byVersion[v].Path, name)
		}
		byVersion[v] = source{Version: v, Path: name}
	}
	srcs := make([]source, 0, len(byVersion))
	for _, s := range byVersion {
		srcs = append(srcs, s)
	}
	sort.Slice(srcs, func(i, j int) bool { return srcs[i].Version < srcs[j].Version })
	return srcs, nil
}

// findSource returns the embedded migration with the given version.
func findSource(srcs []source, version int64) (source, bool) {
	for _, s := range srcs {
		if s.Version == version {
			return s, true
		}
	}
	return source{}, false
}

// fileHash returns the SHA-256 checksum (hex encoded) of the file content at
// path — exactly the bytes goose reads when it applies the migration.
func fileHash(fsys fs.FS, name string) (string, error) {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ChecksumError reports an already-applied migration whose embedded file no
// longer matches the checksum recorded at apply time (ADR-010: migrations
// are immutable; a divergence aborts the run).
type ChecksumError struct {
	Version  int64
	Path     string
	Stored   string // checksum recorded in the log when the migration was applied
	Embedded string // checksum of the file embedded in this binary
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf(
		"refusing to migrate: applied migration %q (version %d) was modified after it was applied: checksum recorded in %s is %s, embedded file hashes to %s (ADR-010 requires immutable migrations)",
		e.Path, e.Version, checksumLogTable, e.Stored, e.Embedded)
}

// MigrationMissingError reports an applied migration whose embedded file has
// been deleted from the migration set.
type MigrationMissingError struct {
	Version int64
}

func (e *MigrationMissingError) Error() string {
	return fmt.Sprintf(
		"refusing to migrate: applied migration version %d is recorded in %s but missing from the embedded migrations (ADR-010 requires immutable migrations)",
		e.Version, checksumLogTable)
}

// verifyApplied is the verify-before step (concept ch. 4.4 point 3): every
// already-applied migration recorded in the checksum log must still exist
// among the embedded files with identical content. It is pure and runs
// before goose is allowed to touch the database.
func verifyApplied(fsys fs.FS, rows []logRow, srcs []source) error {
	for _, row := range rows {
		src, ok := findSource(srcs, row.Version)
		if !ok {
			return &MigrationMissingError{Version: row.Version}
		}
		got, err := fileHash(fsys, src.Path)
		if err != nil {
			return err
		}
		if got != row.FileHash {
			return &ChecksumError{Version: row.Version, Path: src.Path, Stored: row.FileHash, Embedded: got}
		}
	}
	return nil
}

// pendingMigrations returns the embedded migrations that goose would apply,
// in version order. Inserting a migration with a version below the highest
// applied one is rejected like goose rejects out-of-order migrations, so a
// dry run predicts a real run faithfully.
func pendingMigrations(srcs []source, gooseApplied map[int64]time.Time) ([]PendingMigration, error) {
	appliedSet := make(map[int64]bool, len(gooseApplied))
	var maxApplied int64
	for v := range gooseApplied {
		appliedSet[v] = true
		if v > maxApplied {
			maxApplied = v
		}
	}
	var pending []PendingMigration
	for _, s := range srcs {
		if appliedSet[s.Version] {
			continue
		}
		if s.Version < maxApplied {
			return nil, fmt.Errorf(
				"migration %q (version %d) is older than the highest applied version %d but was never applied — refusing to migrate out of order",
				s.Path, s.Version, maxApplied)
		}
		pending = append(pending, PendingMigration(s))
	}
	return pending, nil
}
