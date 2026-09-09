package main

// Integration tests of the WP-3.05 inventory CLI + commit use case
// (DEV-060, ARCH-003 §1.3/§5) against a real short-lived PostgreSQL:
// the `inventory validate|preview|import` command paths and the commit
// semantics they drive — the one-transaction commit (additive upserts on
// UQ (source, external_id) / UQ (asset_id, natural_key), the
// inventory.import audit event, exactly one matching.rebuild outbox job
// per changed commit with the rule_version + inventory_snapshot dedupe
// key), the idempotent no-op re-commit and the atomic rollback on a
// failing outbox append.
//
// The tests drive the CLI through run() with in-memory writers (runCLI,
// cli_test.go) exactly like the other command integration tests, against
// a fresh database migrated through the CLI itself; the commit rollback
// test drives Service.CommitInventory directly with the decorated
// failing-outbox composition of the ARCH-001 §5 tests
// (newCreateSignalService + failingOutboxRepo — every other port real).
// The database server is the compose `db` service or any PostgreSQL
// reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is reachable
// the tests skip (newTestDB), so `go test ./...` stays green on machines
// without the environment.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// inventoryITHeader is the canonical ARCH-003 §1.3 header of the test
// files.
const inventoryITHeader = "source,external_id,type,name,environment,criticality,exposure,owner,vendor,product,version,cpe,purl,image,digest"

// writeInventoryITFile writes one inventory CSV (header + rows) into a
// temp file and returns its path.
func writeInventoryITFile(t *testing.T, rows ...string) string {
	t.Helper()
	content := inventoryITHeader + "\n" + strings.Join(rows, "\n") + "\n"
	path := filepath.Join(t.TempDir(), "inventory.csv")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write inventory file: %v", err)
	}
	return path
}

// inventoryITRow renders one data row from its 15 canonical-order fields.
func inventoryITRow(f ...string) string {
	if len(f) != 15 {
		panic("inventoryITRow: want 15 fields")
	}
	return strings.Join(f, ",")
}

// inventoryITVendorRow is one vendor/product/version-only row.
func inventoryITVendorRow(external, name, vendor, product, version string) string {
	return inventoryITRow("cmdb", external, "server_vm", name, "production", "high", "internet", "", vendor, product, version, "", "", "", "")
}

// TestInventoryCLIValidatePreviewImportLifecycle drives the whole
// DEV-060 CLI pipeline on one real database: validate (positioned
// report, no database state touched), preview (created diff, nothing
// written), import without a commit flag (the mandatory dry run —
// nothing written), import --commit (rows + audit + one matching.rebuild
// with the §5 dedupe key), the identical re-commit (idempotent no-op: no
// row rewritten, no second job) and a changed commit (update + a fresh
// rebuild with a different dedupe key).
func TestInventoryCLIValidatePreviewImportLifecycle(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	code, stdout, stderr := runCLI(t, env, "maintenance", "migrate", "--output", "json")
	if code != exitOK {
		t.Fatalf("migrate exit code = %d (stderr: %s)", code, stderr)
	}

	digest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rows := []string{
		inventoryITVendorRow("a1", "Portal-Host", "acme", "portal", "2.4.4"),
		inventoryITRow("cmdb", "a2", "container_image", "Registry-X", "production", "high", "internal", "", "", "", "", "", "", "registry/x/img:v1", digest),
	}
	file := writeInventoryITFile(t, rows...)

	// validate: positioned report, no database state touched, exit 0.
	code, stdout, stderr = runCLI(t, env, "inventory", "validate", file, "--output", "json")
	if code != exitOK {
		t.Fatalf("validate exit code = %d (stderr: %s)", code, stderr)
	}
	var val inventoryValidateResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &val)
	if val.Rows != 2 || val.ErrorCount != 0 || len(val.Errors) != 0 {
		t.Fatalf("validate result = %+v, want 2 clean rows", val)
	}

	// preview on the empty database: every row created, read-only.
	code, stdout, stderr = runCLI(t, env, "inventory", "preview", file, "--output", "json")
	if code != exitOK {
		t.Fatalf("preview exit code = %d (stderr: %s)", code, stderr)
	}
	var prev inventoryPreviewResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &prev)
	if prev.Assets.Created != 2 || prev.Assets.Updated != 0 || prev.Assets.Unchanged != 0 {
		t.Fatalf("preview assets = %+v, want 2 created", prev.Assets)
	}
	if prev.Components.Created != 2 || len(prev.AssetDiffs) != 2 {
		t.Fatalf("preview components = %+v, diffs = %d, want 2 created / 2 diffs", prev.Components, len(prev.AssetDiffs))
	}

	// import without a commit flag: the mandatory dry run — same report,
	// nothing written.
	code, stdout, stderr = runCLI(t, env, "inventory", "import", file, "--output", "json")
	if code != exitOK {
		t.Fatalf("import dry-run exit code = %d (stderr: %s)", code, stderr)
	}
	var dry inventoryImportResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &dry)
	if !dry.DryRun || dry.Committed || dry.Changed {
		t.Fatalf("dry-run markers = %+v, want dry_run only", dry)
	}
	if dry.Assets.Created != 2 {
		t.Fatalf("dry-run assets = %+v, want the preview tally", dry.Assets)
	}
	pool := openPoolForTest(t, dbURL)
	if n := inventoryCount(t, pool, "assets"); n != 0 {
		t.Fatalf("assets after dry run = %d, want 0 (nothing written)", n)
	}

	// import --commit: the one-transaction commit.
	code, stdout, stderr = runCLI(t, env, "inventory", "import", file, "--commit", "--output", "json")
	if code != exitOK {
		t.Fatalf("import --commit exit code = %d (stderr: %s)", code, stderr)
	}
	var committed inventoryImportResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &committed)
	if committed.DryRun || !committed.Committed || !committed.Changed {
		t.Fatalf("commit markers = %+v, want committed+changed", committed)
	}
	if committed.Assets.Created != 2 || committed.Components.Created != 2 {
		t.Fatalf("commit tallies = assets %+v components %+v, want 2/2 created", committed.Assets, committed.Components)
	}
	if committed.ImportID == "" || committed.RuleVersion != "a0000000000d0000000000" || len(committed.InventorySnapshot) != 64 {
		t.Fatalf("commit job description = import %q rule %q snapshot %q", committed.ImportID, committed.RuleVersion, committed.InventorySnapshot)
	}
	if inventoryCount(t, pool, "assets") != 2 || inventoryCount(t, pool, "components") != 2 {
		t.Fatalf("assets/components after commit = %d/%d, want 2/2", inventoryCount(t, pool, "assets"), inventoryCount(t, pool, "components"))
	}
	// The natural keys of the stored rows match the parser derivation —
	// verify through the inventory_import_validate proof: a second commit
	// of the same file is a no-op, which it can only be when the stored
	// keys equal the derived keys.

	// The audit row: one inventory.import event, aggregate id = import id.
	audit, err := auditInventoryImports(t, pool)
	if err != nil {
		t.Fatalf("read audit rows: %v", err)
	}
	if len(audit) != 1 || audit[0] != committed.ImportID {
		t.Fatalf("inventory.import audit rows = %v, want exactly the import id %s", audit, committed.ImportID)
	}

	// The outbox: exactly one matching.rebuild with the §5 dedupe key
	// rule_version + inventory_snapshot (type-prefixed).
	jobType, dedupeKey := outboxRebuildJob(t, pool)
	if jobType != application.EventTypeMatchingRebuild {
		t.Fatalf("outbox job type = %q, want matching.rebuild", jobType)
	}
	if dedupeKey != "matching.rebuild:a0000000000d0000000000:"+committed.InventorySnapshot {
		t.Fatalf("outbox dedupe_key = %q, want matching.rebuild:a0000000000d0000000000:%s", dedupeKey, committed.InventorySnapshot)
	}

	// Re-commit of the identical file: idempotent no-op — exit 0, nothing
	// changed, no row rewritten, no second rebuild job, one more audit
	// row documenting the attempt.
	code, stdout, stderr = runCLI(t, env, "inventory", "import", file, "--yes", "--output", "json")
	if code != exitOK {
		t.Fatalf("re-commit exit code = %d (stderr: %s)", code, stderr)
	}
	var recommitted inventoryImportResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &recommitted)
	if !recommitted.Committed || recommitted.Changed {
		t.Fatalf("re-commit markers = %+v, want a committed no-op (changed false)", recommitted)
	}
	if recommitted.Assets.Created != 0 || recommitted.Assets.Updated != 0 || recommitted.Assets.Unchanged != 2 {
		t.Fatalf("re-commit tallies = %+v, want 2 unchanged", recommitted.Assets)
	}
	if recommitted.RuleVersion != "" || recommitted.InventorySnapshot != "" {
		t.Fatalf("no-op re-commit describes a rebuild (%q/%q)", recommitted.RuleVersion, recommitted.InventorySnapshot)
	}
	if inventoryCount(t, pool, "assets") != 2 || inventoryCount(t, pool, "components") != 2 {
		t.Fatalf("asset/component counts moved on the no-op re-commit: %d/%d",
			inventoryCount(t, pool, "assets"), inventoryCount(t, pool, "components"))
	}
	if jobType, _ := outboxRebuildJob(t, pool); jobType != application.EventTypeMatchingRebuild {
		t.Fatalf("outbox changed on the no-op re-commit (type %q)", jobType)
	}
	if n := countTableRows(t, pool, "outbox"); n != 1 {
		t.Fatalf("outbox rows after re-commit = %d, want exactly 1 (no rebuild for a no-op)", n)
	}
	audit, err = auditInventoryImports(t, pool)
	if err != nil {
		t.Fatalf("read audit rows: %v", err)
	}
	if len(audit) != 2 {
		t.Fatalf("audit rows after re-commit = %d, want 2 (one per commit attempt)", len(audit))
	}

	// A changed commit (asset rename): one updated asset, a fresh
	// matching.rebuild with a different dedupe key (the snapshot moved).
	time.Sleep(10 * time.Millisecond) // the real clock must advance past the first stamp
	renamed := writeInventoryITFile(t,
		inventoryITVendorRow("a1", "Portal-Host-Renamed", "acme", "portal", "2.4.4"),
		inventoryITRow("cmdb", "a2", "container_image", "Registry-X", "production", "high", "internal", "", "", "", "", "", "", "registry/x/img:v1", digest),
	)
	code, stdout, stderr = runCLI(t, env, "inventory", "import", renamed, "--commit", "--output", "json")
	if code != exitOK {
		t.Fatalf("changed commit exit code = %d (stderr: %s)", code, stderr)
	}
	var changed inventoryImportResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &changed)
	if !changed.Changed || changed.Assets.Updated != 1 || changed.Assets.Unchanged != 1 || changed.Assets.Created != 0 {
		t.Fatalf("changed commit tallies = %+v, want 1 updated + 1 unchanged", changed.Assets)
	}
	if changed.InventorySnapshot == recommitted.InventorySnapshot || changed.InventorySnapshot == committed.InventorySnapshot {
		t.Fatal("changed commit must derive a fresh inventory snapshot")
	}
	if n := countTableRows(t, pool, "outbox"); n != 2 {
		t.Fatalf("outbox rows after the changed commit = %d, want 2", n)
	}

	// A preview of the current file now classifies every row unchanged:
	// preview and commit agree on the natural keys (DEV-059 cross-check).
	code, stdout, stderr = runCLI(t, env, "inventory", "preview", renamed, "--output", "json")
	if code != exitOK {
		t.Fatalf("preview after commits exit code = %d (stderr: %s)", code, stderr)
	}
	var after inventoryPreviewResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &after)
	if after.Assets.Created != 0 || after.Assets.Updated != 0 || after.Assets.Unchanged != 2 {
		t.Fatalf("preview after commits = %+v, want 2 unchanged", after.Assets)
	}
	if after.Components.Created != 0 || after.Components.Updated != 0 || after.Components.Unchanged != 2 {
		t.Fatalf("preview components after commits = %+v, want 2 unchanged", after.Components)
	}
}

// TestInventoryCLIValidatePositionedErrors drives the positioned error
// report of validate: a bad enum row and a malformed identifier are
// reported with their line/column, never abort the file, and never write.
func TestInventoryCLIValidatePositionedErrors(t *testing.T) {
	file := writeInventoryITFile(t,
		inventoryITVendorRow("a1", "Portal-Host", "acme", "portal", "2.4.4"),
		inventoryITRow("cmdb", "a2", "car", "Bad-Host", "production", "high", "internet", "", "acme", "legacy", "1.0", "", "", "", ""),       // bad type
		inventoryITRow("cmdb", "a3", "server_vm", "Bad-Cpe", "production", "high", "internet", "", "", "", "", "cpe:2.3:broken", "", "", ""), // bad cpe
	)

	code, stdout, stderr := runCLI(t, nil, "inventory", "validate", file, "--output", "json")
	if code != exitOK {
		t.Fatalf("validate exit code = %d (stderr: %s)", code, stderr)
	}
	var val inventoryValidateResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &val)
	if val.Rows != 3 || val.ErrorCount != 2 || len(val.Errors) != 2 {
		t.Fatalf("validate result = %+v, want 3 rows with 2 positioned errors", val)
	}
	byLine := map[int]inventoryProblemView{}
	for _, p := range val.Errors {
		byLine[p.Line] = p
	}
	if p := byLine[3]; p.Column != "type" || p.Reason == "" {
		t.Fatalf("line 3 problem = %+v, want the type column", p)
	}
	if p := byLine[4]; p.Column != "cpe" || p.Reason == "" {
		t.Fatalf("line 4 problem = %+v, want the cpe column", p)
	}

	// The text form renders the same positions human-readably.
	code, stdout, _ = runCLI(t, nil, "inventory", "validate", file)
	if code != exitOK {
		t.Fatalf("text validate exit code = %d", code)
	}
	if !strings.Contains(stdout, "line 3, column type") || !strings.Contains(stdout, "line 4, column cpe") {
		t.Fatalf("text validate stdout = %q, want the positioned problems", stdout)
	}
}

// TestInventoryCommitRollsBackOnOutboxFailure is the real-database
// atomicity proof of the commit (ARCH-003 §1.3 — the §5 fault seam
// mirroring the ARCH-001 §5 rollback proof): the decorated failing
// outbox repo fails the matching.rebuild append after the upserts and
// the audit write of the same transaction succeeded; the commit must roll
// everything back — no assets, no components, no audit row, no outbox
// row (TR-004).
func TestInventoryCommitRollsBackOnOutboxFailure(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)
	faulty := &failingOutboxRepo{OutboxRepo: repo.NewOutboxRepo(q), cause: errors.New("outbox append failed (injected)")}
	svc := newCreateSignalService(pool, faulty, clock.RealClock{})

	csv := inventoryITHeader + "\n" + inventoryITVendorRow("a1", "Portal-Host", "acme", "portal", "2.4.4") + "\n"
	if _, err := svc.CommitInventory(ctx, application.CommitInventoryInput{File: []byte(csv)}); err == nil {
		t.Fatal("commit with a failing outbox append must error")
	}
	if faulty.calls != 1 {
		t.Fatalf("failing outbox append calls = %d, want 1", faulty.calls)
	}
	if n := countTableRows(t, pool, "assets"); n != 0 {
		t.Fatalf("assets after the rollback = %d, want 0", n)
	}
	if n := countTableRows(t, pool, "components"); n != 0 {
		t.Fatalf("components after the rollback = %d, want 0", n)
	}
	if n := countTableRows(t, pool, "audit_events"); n != 0 {
		t.Fatalf("audit rows after the rollback = %d, want 0 (audit commits atomically with the state)", n)
	}
	if n := countTableRows(t, pool, "outbox"); n != 0 {
		t.Fatalf("outbox rows after the rollback = %d, want 0", n)
	}
}

// TestInventoryImportRequiresCommitFlag verifies the confirmation gate of
// import: without --commit/--yes the command is the mandatory dry run and
// never writes, even on a database where a commit would change rows.
func TestInventoryImportRequiresCommitFlag(t *testing.T) {
	dbURL := newTestDB(t)
	env := cliDBEnv(dbURL)
	if code, _, stderr := runCLI(t, env, "maintenance", "migrate", "--output", "json"); code != exitOK {
		t.Fatalf("migrate exit code != 0 (stderr: %s)", stderr)
	}
	file := writeInventoryITFile(t, inventoryITVendorRow("a1", "Portal-Host", "acme", "portal", "2.4.4"))
	pool := openPoolForTest(t, dbURL)

	code, stdout, stderr := runCLI(t, env, "inventory", "import", file, "--output", "json")
	if code != exitOK {
		t.Fatalf("import exit code = %d (stderr: %s)", code, stderr)
	}
	var res inventoryImportResult
	decodeJSONStrict(t, string(decodeEnvelope(t, stdout).Result), &res)
	if !res.DryRun || res.Committed {
		t.Fatalf("markers = %+v, want the dry run", res)
	}
	if inventoryCount(t, pool, "assets") != 0 {
		t.Fatal("an import without --commit/--yes must never write")
	}

	// The text form states the dry-run verdict.
	code, stdout, _ = runCLI(t, env, "inventory", "import", file)
	if code != exitOK {
		t.Fatalf("text import exit code = %d", code)
	}
	if !strings.Contains(stdout, "dry run") || !strings.Contains(stdout, "nothing written") {
		t.Fatalf("text import stdout = %q, want the dry-run verdict", stdout)
	}
}

// ---------------------------------------------------------------------------
// helpers

// openPoolForTest opens a pool on the scratch database of a CLI test.
func openPoolForTest(t *testing.T, dbURL string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// inventoryCount counts the rows of the assets/components tables.
func inventoryCount(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// outboxRebuildJob reads the single matching.rebuild job the tests
// expect to exist (type + dedupe key). A missing job fails the test.
func outboxRebuildJob(t *testing.T, pool *pgxpool.Pool) (jobType, dedupeKey string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.QueryRow(ctx,
		"SELECT type, dedupe_key FROM outbox WHERE type = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
		application.EventTypeMatchingRebuild).Scan(&jobType, &dedupeKey); err != nil {
		t.Fatalf("read matching.rebuild job: %v", err)
	}
	return jobType, dedupeKey
}

// auditInventoryImports returns the aggregate ids of the
// inventory.import audit rows in commit order.
func auditInventoryImports(t *testing.T, pool *pgxpool.Pool) ([]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := pool.Query(ctx,
		"SELECT aggregate_id::text FROM audit_events WHERE action = $1 ORDER BY occurred_at, id",
		application.AuditActionInventoryImport)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
