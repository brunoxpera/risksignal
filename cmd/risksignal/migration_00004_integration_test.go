package main

// Integration test of the WP-2.02 migration 00004 at the composition root
// (DEV-028): the raw_records.payload jsonb -> bytea backfill must survive a
// real migration over the I1b schema. cmd/risksignal is the composition root
// that may wire the embedded migration set (db/migrations) together with the
// runner, so the real files are exercised here.
//
// The test migrates a scratch database up to 00003 (the I1b schema, applied
// from the real embedded files), seeds one synthetic raw_records row with a
// jsonb payload exactly like the I1b demo does, applies the remaining
// embedded migrations (00004) and asserts that the payload survives as
// bytea: the stored bytes decode back to exactly the jsonb text that was
// stored before the migration, the column type is bytea and the row is
// stamped content_encoding = 'json' (00004 marks every converted row, which
// was a jsonb document by construction, self-describing).
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
)

// migrationFSUpTo returns the real embedded migration files up to and
// including version upto as a filesystem, so a test can apply an earlier
// schema state (e.g. the I1b state 00001..00003) before the later embedded
// migrations exist for the runner. The file bytes are the embedded bytes,
// so checksums recorded from this filesystem match the full embedded set.
func migrationFSUpTo(t *testing.T, upto int64) fs.FS {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	m := fstest.MapFS{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			t.Fatalf("migration file %q has no version prefix", name)
		}
		v, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatalf("migration file %q: invalid version prefix: %v", name, err)
		}
		if v > upto {
			continue
		}
		data, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatalf("read embedded migration %s: %v", name, err)
		}
		m[name] = &fstest.MapFile{Data: data}
	}
	return m
}

func TestMigration00004BackfillsPayloadJSONBToBytea(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: apply the real I1b migration set (00001..00003).
	runner, err := migrate.Open(ctx, dbURL, migrationFSUpTo(t, 3))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 3 {
		t.Fatalf("apply I1b migrations: res=%+v err=%v", res, err)
	}
	_ = runner.Close()

	// Step 2: seed one synthetic raw record with a jsonb payload, exactly
	// like the I1b demo chain does, and remember the canonical jsonb text.
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	const doc = `{"external_id": "i1b-doc", "cases": [{"cve_id": "CVE-2024-9001", "summary": "backfill probe"}]}`
	var payloadText string
	if err := db.QueryRowContext(ctx, `
		WITH src AS (
			INSERT INTO sources (type, name) VALUES ('synthetic', 'dev028-backfill')
			RETURNING id
		)
		INSERT INTO raw_records (source_id, external_id, content_hash, payload, fetched_at)
		SELECT id, 'i1b-doc', 'dev028-backfill-hash', $1::jsonb, now() FROM src
		RETURNING payload::text`, doc).Scan(&payloadText); err != nil {
		t.Fatalf("seed I1b raw record: %v", err)
	}
	if payloadText == "" {
		t.Fatal("seeded raw record has empty jsonb payload")
	}

	// Step 3: apply the remaining embedded migrations (00004).
	runner, err = migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer runner.Close()
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("apply 00004: %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].Version != 4 {
		t.Fatalf("applied = %+v, want exactly version 4", res.Applied)
	}

	// Step 4: the payload survived as bytea and decodes back to exactly the
	// text that was stored before the migration; the row is stamped
	// content_encoding = 'json' (it was a jsonb document by construction).
	var typ, decoded, encoding string
	if err := db.QueryRowContext(ctx,
		"SELECT pg_typeof(payload), convert_from(payload, 'UTF8'), content_encoding FROM raw_records WHERE external_id = 'i1b-doc'",
	).Scan(&typ, &decoded, &encoding); err != nil {
		t.Fatalf("read backfilled row: %v", err)
	}
	if typ != "bytea" {
		t.Fatalf("payload type = %q, want bytea", typ)
	}
	if decoded != payloadText {
		t.Fatalf("decoded payload = %q, want the pre-migration jsonb text %q", decoded, payloadText)
	}
	if encoding != "json" {
		t.Fatalf("content_encoding = %q, want json (converted row was a jsonb document)", encoding)
	}

	// The quarantine and epss_current tables landed with the same migration.
	for _, table := range []string{"quarantine", "epss_current"} {
		var reg *string
		if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)", table).Scan(&reg); err != nil {
			t.Fatalf("to_regclass(%s): %v", table, err)
		}
		if reg == nil {
			t.Fatalf("table %s missing after 00004", table)
		}
	}
}
