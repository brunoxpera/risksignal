package export_test

// Unit tests for the export spool (ARCH-007 §1.2, WP-6.04 / DEV-115): the
// export.dir-relative artifact write/read, the SHA-256 checksum and the path
// safety (an absolute path or one that escapes the spool root is rejected).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application/export"
)

func TestSpoolWriteReadChecksum(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	spool := export.NewSpool(dir)

	content := []byte("id,cve_id,priority\n1,CVE-2024-0001,P1\n")
	key := export.ArtifactKey("abc-123", export.FormatCSV)

	art, err := spool.Write(ctx, key, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if art.Path != key {
		t.Fatalf("artifact path = %q, want %q", art.Path, key)
	}
	if art.SizeBytes != int64(len(content)) {
		t.Fatalf("size = %d, want %d", art.SizeBytes, len(content))
	}
	sum := sha256.Sum256(content)
	if art.Checksum != hex.EncodeToString(sum[:]) {
		t.Fatalf("checksum = %q, want %q", art.Checksum, hex.EncodeToString(sum[:]))
	}

	rc, err := spool.Open(ctx, art.Path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("read %q, want %q", got, content)
	}
}

func TestSpoolRejectsEscapingPaths(t *testing.T) {
	ctx := context.Background()
	spool := export.NewSpool(t.TempDir())

	for _, bad := range []string{"../escape.csv", "/etc/passwd", "a/../../b.csv", ".", "", "  "} {
		if _, err := spool.Write(ctx, bad, strings.NewReader("x")); err == nil {
			t.Errorf("Write accepted unsafe key %q", bad)
		}
		if _, err := spool.Open(ctx, bad); err == nil {
			t.Errorf("Open accepted unsafe path %q", bad)
		}
	}
}

func TestSpoolOpenMissingArtifact(t *testing.T) {
	spool := export.NewSpool(t.TempDir())
	if _, err := spool.Open(context.Background(), "missing.csv"); err == nil {
		t.Fatal("Open accepted a missing artifact")
	}
}

func TestSpoolUnconfiguredDirectory(t *testing.T) {
	spool := export.NewSpool("")
	if _, err := spool.Write(context.Background(), "k.csv", strings.NewReader("x")); err == nil {
		t.Fatal("Write accepted an unconfigured spool directory")
	}
}
