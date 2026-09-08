package migrate

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		want    int64
		wantErr bool
	}{
		{"00001_schema_migration_log.sql", 1, false},
		{"00012_create_widgets.sql", 12, false},
		{"1_x.sql", 1, false},
		{"noprefix.sql", 0, true},
		{"abc_01_x.sql", 0, true},
		{"0_x.sql", 0, true},
		{"-1_x.sql", 0, true},
		{"00001.sql", 0, true}, // missing underscore separator
	}
	for _, tt := range tests {
		got, err := parseVersion(tt.name)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseVersion(%q): expected error, got %d", tt.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseVersion(%q): unexpected error: %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseVersion(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestListSources(t *testing.T) {
	fsys := fstest.MapFS{
		"00001_first.sql":  {Data: []byte("-- +goose Up\nSELECT 1;\n")},
		"00002_second.sql": {Data: []byte("-- +goose Up\nSELECT 2;\n")},
	}
	srcs, err := listSources(fsys)
	if err != nil {
		t.Fatalf("listSources: %v", err)
	}
	if len(srcs) != 2 || srcs[0].Version != 1 || srcs[1].Version != 2 {
		t.Fatalf("listSources = %+v, want versions [1 2] in order", srcs)
	}

	// Duplicate versions are rejected, like goose rejects them.
	dup := fstest.MapFS{
		"00001_first.sql": {Data: []byte("-- +goose Up\nSELECT 1;\n")},
		"00001_again.sql": {Data: []byte("-- +goose Up\nSELECT 1;\n")},
	}
	if _, err := listSources(dup); err == nil || !strings.Contains(err.Error(), "duplicate migration version 1") {
		t.Fatalf("listSources(dup) error = %v, want duplicate-version error", err)
	}

	// Unparseable names are rejected, like goose ignores them only silently.
	bad := fstest.MapFS{"readme.sql": {Data: []byte("-- +goose Up\nSELECT 1;\n")}}
	if _, err := listSources(bad); err == nil {
		t.Fatal("listSources(bad name): expected error")
	}
}

func TestFileHash(t *testing.T) {
	// sha256("hello\n") — fixed vector so the test does not re-implement the
	// function under test.
	const want = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	fsys := fstest.MapFS{"f.sql": {Data: []byte("hello\n")}}
	got, err := fileHash(fsys, "f.sql")
	if err != nil {
		t.Fatalf("fileHash: %v", err)
	}
	if got != want {
		t.Fatalf("fileHash = %q, want %q", got, want)
	}
}

func TestVerifyApplied(t *testing.T) {
	fsys := fstest.MapFS{
		"00001_first.sql":  {Data: []byte("-- +goose Up\nSELECT 1;\n")},
		"00002_second.sql": {Data: []byte("-- +goose Up\nSELECT 2;\n")},
	}
	srcs, err := listSources(fsys)
	if err != nil {
		t.Fatalf("listSources: %v", err)
	}
	h1, _ := fileHash(fsys, "00001_first.sql")
	h2, _ := fileHash(fsys, "00002_second.sql")

	// Matching rows pass.
	rows := []logRow{{Version: 1, FileHash: h1}, {Version: 2, FileHash: h2}}
	if err := verifyApplied(fsys, rows, srcs); err != nil {
		t.Fatalf("verifyApplied(ok): %v", err)
	}

	// An altered applied migration is a checksum error naming version and
	// both hashes.
	fsys["00002_second.sql"] = &fstest.MapFile{Data: []byte("-- +goose Up\nSELECT 2; -- tampered\n")}
	err = verifyApplied(fsys, rows, srcs)
	var cerr *ChecksumError
	if !errors.As(err, &cerr) {
		t.Fatalf("verifyApplied(altered): error = %v, want *ChecksumError", err)
	}
	if cerr.Version != 2 || cerr.Path != "00002_second.sql" || cerr.Stored != h2 || cerr.Embedded == h2 {
		t.Fatalf("ChecksumError = %+v, want version 2 with differing hashes", cerr)
	}
	if !strings.Contains(err.Error(), "modified after it was applied") {
		t.Fatalf("ChecksumError message = %q, want the immutable-migration wording", err)
	}

	// A logged migration whose file vanished is a missing-migration error.
	// (The runner re-enumerates the embedded files before every run, so the
	// deletion is visible to it.)
	delete(fsys, "00002_second.sql")
	srcsAfter, err := listSources(fsys)
	if err != nil {
		t.Fatalf("listSources: %v", err)
	}
	err = verifyApplied(fsys, rows, srcsAfter)
	var merr *MigrationMissingError
	if !errors.As(err, &merr) || merr.Version != 2 {
		t.Fatalf("verifyApplied(deleted): error = %v, want *MigrationMissingError for version 2", err)
	}
}

func TestPendingMigrations(t *testing.T) {
	srcs := []source{{Version: 1, Path: "00001_a.sql"}, {Version: 2, Path: "00002_b.sql"}, {Version: 3, Path: "00003_c.sql"}}
	applied := map[int64]time.Time{1: time.Now()}

	pending, err := pendingMigrations(srcs, applied)
	if err != nil {
		t.Fatalf("pendingMigrations: %v", err)
	}
	if len(pending) != 2 || pending[0].Version != 2 || pending[1].Version != 3 {
		t.Fatalf("pendingMigrations = %+v, want versions [2 3]", pending)
	}

	// An embedded migration below the highest applied version but never
	// applied is an out-of-order refusal, mirroring goose.
	applied[3] = time.Now()
	_, err = pendingMigrations(srcs, applied)
	if err == nil || !strings.Contains(err.Error(), "out of order") {
		t.Fatalf("pendingMigrations(out-of-order) error = %v, want out-of-order refusal", err)
	}
}
