package repo

// Integration test for the I6 operations schema and queries (ARCH-007
// §1.2/§2.1/§2.2/§2.3, WP-6.02 / DEV-112, migration 00011/00012): the export
// CRUD (insert → read → mark completed / failed → sweep), the retention
// candidate scan (closed + expired signals in, held/open/recent out), the
// legal-hold CRUD (create → active check → release, set-once), the retention
// run lifecycle (dry_run → approved → executing → completed / failed with the
// status gate), and the streaming SignalExportSource read (filtered + ordered
// by the ch. 10.4 sort, including the SLA deadline ordering and the sla_state
// filter).
//
// It runs against a real, short-lived PostgreSQL database created per test
// case and migrated with the embedded set (the shared newI4TestPool helper of
// i4_integration_test.go, same package) — so it also proves migration 00011/
// 00012 apply cleanly on a fresh database and are recorded in the checksum log.
// When no database is reachable the test skips, so `go test ./...` stays green
// on machines without the environment.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
)

// i6SignalSeed describes one seeded signal chain for the I6 query tests.
type i6SignalSeed struct {
	assetType string
	product   string
	cve       string
	priority  string
	status    string
	owner     string // "" = NULL
	createdAt time.Time
	closedAt  time.Time // zero = NULL
	sourceID  string    // "" = no evidencing source
}

// i6Seed inserts the inventory/match/signal chain one I6 test signal needs,
// plus (when sourceID is set) a raw record + nvd_statement evidence attributing
// the vulnerability to that source. It returns the signal id.
func i6Seed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ext string, s i6SignalSeed) string {
	t.Helper()

	var vulnID string
	if err := pool.QueryRow(ctx, `
		WITH a AS (
		    INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure)
		    VALUES ($1, 'i6-seed', $2, $2, 'prod', 'critical', 'internet')
		    RETURNING id
		), c AS (
		    INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, natural_key, version_scheme)
		    SELECT id, 'acme', $3, '1.0', 'acme', $3, 'cpe:acme:' || $3 || ':1.0', 'generic' FROM a
		    RETURNING id
		), v AS (
		    INSERT INTO vulnerabilities (cve_id, summary, published_at)
		    VALUES ($4, $5, now())
		    RETURNING id
		), m AS (
		    INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
		    SELECT v.id, c.id, 'exact_version', 100, 'high', 'i1b-1', now() FROM v, c
		    RETURNING id, vulnerability_id
		)
		SELECT id, vulnerability_id FROM m`, ext, s.assetType, s.product, s.cve, "i6 seed "+s.cve).Scan(new(string), &vulnID); err != nil {
		t.Fatalf("seed chain %s: %v", ext, err)
	}

	var matchID string
	if err := pool.QueryRow(ctx, `SELECT id FROM matches WHERE vulnerability_id = $1`, vulnID).Scan(&matchID); err != nil {
		t.Fatalf("read match id %s: %v", ext, err)
	}

	var owner, closedAt any
	if s.owner != "" {
		owner = s.owner
	}
	if !s.closedAt.IsZero() {
		closedAt = s.closedAt
	}
	var signalID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO risk_signals (match_id, priority, status, owner, closed_at, rule_version, factors, created_at)
		VALUES ($1, $2, $3, $4, $5, 'p0000000001', '{}'::jsonb, $6)
		RETURNING id`, matchID, s.priority, s.status, owner, closedAt, s.createdAt).Scan(&signalID); err != nil {
		t.Fatalf("seed signal %s: %v", ext, err)
	}

	if s.sourceID != "" {
		var rawID string
		if err := pool.QueryRow(ctx, `
			INSERT INTO raw_records (source_id, external_id, content_hash, payload, content_encoding, fetched_at)
			VALUES ($1, $2, $3, $4, 'json', $5)
			RETURNING id`, s.sourceID, "i6-raw-"+ext, "h-"+ext, []byte(`{}`), s.createdAt).Scan(&rawID); err != nil {
			t.Fatalf("seed raw record %s: %v", ext, err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO evidences (vulnerability_id, raw_record_id, type, value, value_hash, observed_at)
			VALUES ($1, $2, 'nvd_statement', '{}'::jsonb, $3, $4)`, vulnID, rawID, "vh-"+ext, s.createdAt); err != nil {
			t.Fatalf("seed evidence %s: %v", ext, err)
		}
	}
	return signalID
}

func TestI6PersistenceIntegration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)
	now := toTS(mustTime("2026-03-20T00:00:00Z"))

	// 0. The fresh database migrated with 00011/00012 — the checksum log must
	// record both versions (ADR-010).
	var logged int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migration_log WHERE version IN (11, 12)`).Scan(&logged); err != nil {
		t.Fatalf("count checksum log for 00011/00012: %v", err)
	}
	if logged != 2 {
		t.Fatalf("checksum log rows for 00011/00012 = %d, want 2", logged)
	}

	// 1. Exports: insert → read → mark completed (stamped) → idempotent
	// re-mark → mark failed → sweep.
	inserted, err := q.InsertExport(ctx, gen.InsertExportParams{
		Filter:    []byte(`{"priority":"P1"}`),
		Format:    "csv",
		CreatedBy: "alice",
		CreatedAt: toTS(mustTime("2026-05-01T00:00:00Z")),
	})
	if err != nil {
		t.Fatalf("insert export: %v", err)
	}
	if inserted.Status != "pending" || !sameJSON(inserted.Filter, []byte(`{"priority":"P1"}`)) || inserted.Format != "csv" {
		t.Fatalf("inserted export = %+v, want pending csv with the frozen filter", inserted)
	}
	if inserted.StoragePath.Valid || inserted.RowCount.Valid {
		t.Fatalf("pending export has generation stamps: %+v", inserted)
	}
	got, err := q.GetExport(ctx, inserted.ID)
	if err != nil {
		t.Fatalf("get export: %v", err)
	}
	if got.ID != inserted.ID {
		t.Fatalf("get export id = %v, want %v", got.ID, inserted.ID)
	}

	completed, err := q.MarkExportCompleted(ctx, gen.MarkExportCompletedParams{
		StoragePath:   toTextOpt("/spool/export-1.csv"),
		RowCount:      pgtype.Int4{Int32: 7, Valid: true},
		SizeBytes:     pgtype.Int8{Int64: 1234, Valid: true},
		Checksum:      toTextOpt("sha256-deadbeef"),
		SchemaVersion: toTextOpt("export-schema-v1"),
		RuleVersion:   toTextOpt("p0000000001"),
		ExpiresAt:     toTS(mustTime("2026-05-08T00:00:00Z")),
		ID:            inserted.ID,
	})
	if err != nil {
		t.Fatalf("mark export completed: %v", err)
	}
	if completed.Status != "completed" || completed.RowCount.Int32 != 7 || completed.SizeBytes.Int64 != 1234 {
		t.Fatalf("completed export = %+v, want completed with the stamped counts", completed)
	}
	// A second completion must match zero rows (the row is already completed).
	if _, err := q.MarkExportCompleted(ctx, gen.MarkExportCompletedParams{ID: inserted.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("re-mark completed export: err = %v, want ErrNoRows", err)
	}

	failed, err := q.InsertExport(ctx, gen.InsertExportParams{
		Filter:    []byte(`{}`),
		Format:    "json",
		CreatedBy: "bob",
		CreatedAt: toTS(mustTime("2026-05-02T00:00:00Z")),
	})
	if err != nil {
		t.Fatalf("insert second export: %v", err)
	}
	failedRow, err := q.MarkExportFailed(ctx, gen.MarkExportFailedParams{ID: failed.ID, LastError: toTextOpt("disk full")})
	if err != nil {
		t.Fatalf("mark export failed: %v", err)
	}
	if failedRow.Status != "failed" || failedRow.LastError.String != "disk full" {
		t.Fatalf("failed export = %+v, want failed with the error", failedRow)
	}

	// The sweep input: only the completed row past its TTL (expires_at <= now).
	expired, err := q.ListExpiredExports(ctx, toTS(mustTime("2026-06-01T00:00:00Z")))
	if err != nil {
		t.Fatalf("list expired exports: %v", err)
	}
	if len(expired) != 1 || expired[0].ID != inserted.ID {
		t.Fatalf("expired exports = %+v, want only the completed export-1", expired)
	}
	expiredRow, err := q.MarkExportExpired(ctx, inserted.ID)
	if err != nil {
		t.Fatalf("mark export expired: %v", err)
	}
	if expiredRow.Status != "expired" {
		t.Fatalf("expired export status = %q, want expired", expiredRow.Status)
	}
	if _, err := q.MarkExportExpired(ctx, inserted.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("re-mark expired export: err = %v, want ErrNoRows", err)
	}

	// 2. Legal holds: create → active → list → release (set-once).
	heldSignal := "11111111-1111-1111-1111-111111111111"
	if held, err := q.HasActiveLegalHold(ctx, gen.HasActiveLegalHoldParams{
		AggregateType: "risk_signal", AggregateID: mustUUID(t, heldSignal),
	}); err != nil || held {
		t.Fatalf("HasActiveLegalHold before create = %v (err %v), want false", held, err)
	}
	hold, err := q.CreateLegalHold(ctx, gen.CreateLegalHoldParams{
		AggregateType: "risk_signal",
		AggregateID:   mustUUID(t, heldSignal),
		Reason:        "litigation hold 2026-05",
		ActorID:       "admin",
		CreatedAt:     toTS(mustTime("2026-05-05T00:00:00Z")),
	})
	if err != nil {
		t.Fatalf("create legal hold: %v", err)
	}
	if hold.ReleasedAt.Valid {
		t.Fatal("fresh hold reported released")
	}
	if active, err := q.HasActiveLegalHold(ctx, gen.HasActiveLegalHoldParams{
		AggregateType: "risk_signal", AggregateID: mustUUID(t, heldSignal),
	}); err != nil || !active {
		t.Fatalf("HasActiveLegalHold after create = %v (err %v), want true", active, err)
	}
	holds, err := q.ListLegalHolds(ctx, gen.ListLegalHoldsParams{Active: pgtype.Bool{Bool: true, Valid: true}})
	if err != nil || len(holds) != 1 {
		t.Fatalf("list active holds = %d (err %v), want 1", len(holds), err)
	}
	released, err := q.ReleaseLegalHold(ctx, gen.ReleaseLegalHoldParams{
		ID: hold.ID, ReleasedAt: toTS(mustTime("2026-05-06T00:00:00Z")),
	})
	if err != nil {
		t.Fatalf("release legal hold: %v", err)
	}
	if !released.ReleasedAt.Valid {
		t.Fatal("released hold has no released_at")
	}
	if _, err := q.ReleaseLegalHold(ctx, gen.ReleaseLegalHoldParams{
		ID: hold.ID, ReleasedAt: toTS(mustTime("2026-05-07T00:00:00Z")),
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("re-release hold: err = %v, want ErrNoRows (set-once)", err)
	}
	if active, err := q.HasActiveLegalHold(ctx, gen.HasActiveLegalHoldParams{
		AggregateType: "risk_signal", AggregateID: mustUUID(t, heldSignal),
	}); err != nil || active {
		t.Fatalf("HasActiveLegalHold after release = %v (err %v), want false", active, err)
	}

	// 3. Retention candidates: seed an evidencing source, then signals.
	srcID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{Type: "synthetic", Name: "i6-src", Enabled: true})
	if err != nil {
		t.Fatalf("upsert source: %v", err)
	}
	src := uuidString(srcID)

	s1 := i6Seed(t, ctx, pool, "i6-a1", i6SignalSeed{assetType: "server", product: "widget", cve: "CVE-2026-1001", priority: "P1", status: "new", owner: "alice", createdAt: mustTime("2026-01-01T00:00:00Z"), sourceID: src})
	s2 := i6Seed(t, ctx, pool, "i6-a2", i6SignalSeed{assetType: "database", product: "gizmo", cve: "CVE-2026-1002", priority: "P2", status: "resolved", owner: "bob", createdAt: mustTime("2026-02-01T00:00:00Z"), closedAt: mustTime("2026-02-10T00:00:00Z"), sourceID: src})
	s3 := i6Seed(t, ctx, pool, "i6-a3", i6SignalSeed{assetType: "server", product: "gizmo", cve: "CVE-2026-1003", priority: "P2", status: "accepted", owner: "alice", createdAt: mustTime("2026-03-01T00:00:00Z"), closedAt: mustTime("2026-03-05T00:00:00Z")})
	s4 := i6Seed(t, ctx, pool, "i6-a4", i6SignalSeed{assetType: "server", product: "widget", cve: "CVE-2026-1004", priority: "P3", status: "resolved", owner: "carol", createdAt: mustTime("2026-04-01T00:00:00Z"), closedAt: mustTime("2026-04-05T00:00:00Z")})

	// Give s3 an open SLA clock with a past deadline so the deadline ordering
	// and the sla_state filter are exercised.
	if _, err := pool.Exec(ctx, `
		INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at)
		VALUES ($1, 'assessment', $2, $3)`, s3, mustTime("2026-03-01T00:00:00Z"), mustTime("2026-03-10T00:00:00Z")); err != nil {
		t.Fatalf("seed sla clock: %v", err)
	}
	// Hold s4 so it is excluded from the candidate scan.
	if _, err := q.CreateLegalHold(ctx, gen.CreateLegalHoldParams{
		AggregateType: "risk_signal", AggregateID: mustUUID(t, s4), Reason: "hold s4", ActorID: "admin",
		CreatedAt: toTS(mustTime("2026-05-01T00:00:00Z")),
	}); err != nil {
		t.Fatalf("hold s4: %v", err)
	}

	candidates, err := q.ListRetentionCandidates(ctx, toTS(mustTime("2026-03-15T00:00:00Z")))
	if err != nil {
		t.Fatalf("list retention candidates: %v", err)
	}
	if got := retentionCandidateIDs(candidates); !slices.Equal(got, []string{s2, s3}) {
		t.Fatalf("retention candidates = %v, want [%s %s] (closed+expired in; held/open/recent out)", got, s2, s3)
	}

	// 4. Retention runs: dry_run → approved → executing → completed; a second
	// run fails; the execution gate rejects an un-approved run.
	run, err := q.InsertRetentionRun(ctx, gen.InsertRetentionRunParams{
		PolicyID: "closed-signals-5y", Stage: "delete", Cutoff: toTS(mustTime("2026-03-15T00:00:00Z")),
		PartitionKey: "2026-03", Status: "dry_run", DryRun: []byte(`{"candidates":2,"held":1,"to_pseudonymise":0,"to_delete":2}`),
	})
	if err != nil {
		t.Fatalf("insert retention run: %v", err)
	}
	if run.Status != "dry_run" || len(run.DryRun) == 0 {
		t.Fatalf("inserted run = %+v, want dry_run with the report", run)
	}
	// The execution gate: executing an un-approved run matches zero rows.
	if _, err := q.MarkRetentionRunExecuting(ctx, gen.MarkRetentionRunExecutingParams{ID: run.ID, StartedAt: toTS(mustTime("2026-03-16T00:00:00Z"))}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("execute un-approved run: err = %v, want ErrNoRows", err)
	}
	approved, err := q.MarkRetentionRunApproved(ctx, gen.MarkRetentionRunApprovedParams{
		ID: run.ID, ApprovedBy: toTextOpt("po"), ApprovedAt: toTS(mustTime("2026-03-16T00:00:00Z")), ApprovalReason: toTextOpt("due"),
	})
	if err != nil {
		t.Fatalf("approve retention run: %v", err)
	}
	if approved.Status != "approved" {
		t.Fatalf("approved run status = %q, want approved", approved.Status)
	}
	executing, err := q.MarkRetentionRunExecuting(ctx, gen.MarkRetentionRunExecutingParams{ID: run.ID, StartedAt: toTS(mustTime("2026-03-17T00:00:00Z"))})
	if err != nil {
		t.Fatalf("execute retention run: %v", err)
	}
	if executing.Status != "executing" {
		t.Fatalf("executing run status = %q, want executing", executing.Status)
	}
	finished, err := q.MarkRetentionRunCompleted(ctx, gen.MarkRetentionRunCompletedParams{
		ID: run.ID, FinishedAt: toTS(mustTime("2026-03-17T01:00:00Z")),
		PseudonymisedCount: 0, DeletedCount: 2, FailedCount: 0,
	})
	if err != nil {
		t.Fatalf("complete retention run: %v", err)
	}
	if finished.Status != "completed" || finished.DeletedCount != 2 {
		t.Fatalf("completed run = %+v, want completed with deleted_count 2", finished)
	}
	readBack, err := q.GetRetentionRun(ctx, run.ID)
	if err != nil || readBack.ID != run.ID {
		t.Fatalf("get retention run: %+v (err %v)", readBack, err)
	}

	run2, err := q.InsertRetentionRun(ctx, gen.InsertRetentionRunParams{
		PolicyID: "closed-signals-5y", Stage: "pseudonymise", Cutoff: toTS(mustTime("2026-03-15T00:00:00Z")),
		PartitionKey: "2026-04", Status: "dry_run",
	})
	if err != nil {
		t.Fatalf("insert second run: %v", err)
	}
	if _, err := q.MarkRetentionRunApproved(ctx, gen.MarkRetentionRunApprovedParams{
		ID: run2.ID, ApprovedBy: toTextOpt("po"), ApprovedAt: toTS(mustTime("2026-04-01T00:00:00Z")), ApprovalReason: toTextOpt("due"),
	}); err != nil {
		t.Fatalf("approve second run: %v", err)
	}
	failedRun, err := q.MarkRetentionRunFailed(ctx, gen.MarkRetentionRunFailedParams{
		ID: run2.ID, FinishedAt: toTS(mustTime("2026-04-01T02:00:00Z")), FailedCount: 3, LastError: toTextOpt("batch 3 timed out"),
	})
	if err != nil {
		t.Fatalf("fail second run: %v", err)
	}
	if failedRun.Status != "failed" || failedRun.FailedCount != 3 || failedRun.LastError.String != "batch 3 timed out" {
		t.Fatalf("failed run = %+v, want failed with the counters and error", failedRun)
	}

	// 5. SignalExportSource: unfiltered order is priority → next deadline
	// (NULLS LAST) → created_at; s3 (P2, earlier deadline) sorts before s2 (P2,
	// no clock).
	all, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now})
	if err != nil {
		t.Fatalf("signal export source (unfiltered): %v", err)
	}
	if got := exportRowIDs(all); !slices.Equal(got, []string{s1, s3, s2, s4}) {
		t.Fatalf("unfiltered export order = %v, want [%s %s %s %s] (priority, deadline, created_at)", got, s1, s3, s2, s4)
	}

	byPriority, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, Priority: toTextOpt("P2")})
	if err != nil {
		t.Fatalf("filter by priority: %v", err)
	}
	if got := exportRowIDs(byPriority); !slices.Equal(got, []string{s3, s2}) {
		t.Fatalf("priority P2 export = %v, want [%s %s]", got, s3, s2)
	}

	byAssetType, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, AssetType: toTextOpt("server")})
	if err != nil {
		t.Fatalf("filter by asset_type: %v", err)
	}
	if got := exportRowIDs(byAssetType); !slices.Equal(got, []string{s1, s3, s4}) {
		t.Fatalf("asset_type server export = %v, want [%s %s %s]", got, s1, s3, s4)
	}

	byProduct, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, Product: toTextOpt("widget")})
	if err != nil {
		t.Fatalf("filter by product: %v", err)
	}
	if got := exportRowIDs(byProduct); !slices.Equal(got, []string{s1, s4}) {
		t.Fatalf("product widget export = %v, want [%s %s]", got, s1, s4)
	}

	byCVE, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, Cve: toTextOpt("CVE-2026-1003")})
	if err != nil {
		t.Fatalf("filter by cve: %v", err)
	}
	if got := exportRowIDs(byCVE); !slices.Equal(got, []string{s3}) {
		t.Fatalf("cve export = %v, want [%s]", got, s3)
	}

	byText, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, FreeText: toTextOpt("gizmo")})
	if err != nil {
		t.Fatalf("filter by free_text: %v", err)
	}
	if got := exportRowIDs(byText); !slices.Equal(got, []string{s3, s2}) {
		t.Fatalf("free_text gizmo export = %v, want [%s %s]", got, s3, s2)
	}

	byOwner, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, OwnerID: toTextOpt("alice")})
	if err != nil {
		t.Fatalf("filter by owner: %v", err)
	}
	if got := exportRowIDs(byOwner); !slices.Equal(got, []string{s1, s3}) {
		t.Fatalf("owner alice export = %v, want [%s %s]", got, s1, s3)
	}

	bySource, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, SourceID: srcID})
	if err != nil {
		t.Fatalf("filter by source: %v", err)
	}
	if got := exportRowIDs(bySource); !slices.Equal(got, []string{s1, s2}) {
		t.Fatalf("source export = %v, want [%s %s]", got, s1, s2)
	}

	byBreached, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, SlaState: toTextOpt("breached")})
	if err != nil {
		t.Fatalf("filter by sla_state breached: %v", err)
	}
	if got := exportRowIDs(byBreached); !slices.Equal(got, []string{s3}) {
		t.Fatalf("sla_state breached export = %v, want [%s]", got, s3)
	}
	byNoClock, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, SlaState: toTextOpt("none")})
	if err != nil {
		t.Fatalf("filter by sla_state none: %v", err)
	}
	if got := exportRowIDs(byNoClock); !slices.Equal(got, []string{s1, s2, s4}) {
		t.Fatalf("sla_state none export = %v, want [%s %s %s]", got, s1, s2, s4)
	}

	// 6. Paused clock (DEV-113 corrective): while a clock is paused its
	// effective deadline shifts FORWARD by the elapsed pause
	// (deadline_at + paused_seconds + (now − paused_at)), mirroring
	// ScanDueSlaClocks and domain.SlaClock.EffectiveDeadline — a paused clock
	// is never pulled backward. Two P4 signals sharing product "sprocket":
	// s5 has a paused clock whose raw deadline_at (03-19) is earlier than
	// s6's unpaused clock (03-20), but the accumulated pause pushes s5's
	// effective deadline to 03-21 — so s6 must sort first.
	s5 := i6Seed(t, ctx, pool, "i6-a5", i6SignalSeed{assetType: "server", product: "sprocket", cve: "CVE-2026-1005", priority: "P4", status: "new", owner: "dave", createdAt: mustTime("2026-03-02T00:00:00Z")})
	s6 := i6Seed(t, ctx, pool, "i6-a6", i6SignalSeed{assetType: "server", product: "sprocket", cve: "CVE-2026-1006", priority: "P4", status: "new", owner: "dave", createdAt: mustTime("2026-03-03T00:00:00Z")})
	// s5: paused since 03-18 with the past deadline 03-19 plus 1h accumulated
	// pause → effective 03-19 + 1h + (03-20 − 03-18) = 03-21T01:00, still
	// open; the inverted sign would give 03-17T01:00, breached.
	if _, err := pool.Exec(ctx, `
		INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at, paused_seconds, paused_at)
		VALUES ($1, 'assessment', $2, $3, 3600, $4)`,
		s5, mustTime("2026-03-01T00:00:00Z"), mustTime("2026-03-19T00:00:00Z"), mustTime("2026-03-18T00:00:00Z")); err != nil {
		t.Fatalf("seed paused sla clock: %v", err)
	}
	// s6: the unpaused comparison clock with the later raw deadline 03-20.
	if _, err := pool.Exec(ctx, `
		INSERT INTO sla_clocks (signal_id, target, started_at, deadline_at)
		VALUES ($1, 'assessment', $2, $3)`,
		s6, mustTime("2026-03-01T00:00:00Z"), mustTime("2026-03-20T00:00:00Z")); err != nil {
		t.Fatalf("seed comparison sla clock: %v", err)
	}

	// s5's effective deadline (03-21) is later than s6's (03-20), so s6 sorts
	// first despite s5's earlier raw deadline — the deadline moved forward.
	sprockets, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, Product: toTextOpt("sprocket")})
	if err != nil {
		t.Fatalf("signal export source (sprocket): %v", err)
	}
	if got := exportRowIDs(sprockets); !slices.Equal(got, []string{s6, s5}) {
		t.Fatalf("paused-clock export order = %v, want [%s %s] (effective deadline shifts forward)", got, s6, s5)
	}

	// The paused clock is open, not breached: the inverted sign would place
	// its effective deadline (03-17) in the past and surface it as breached.
	pausedOpen, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, Cve: toTextOpt("CVE-2026-1005"), SlaState: toTextOpt("open")})
	if err != nil {
		t.Fatalf("filter paused clock sla_state open: %v", err)
	}
	if got := exportRowIDs(pausedOpen); !slices.Equal(got, []string{s5}) {
		t.Fatalf("paused clock sla_state open = %v, want [%s]", got, s5)
	}
	pausedBreached, err := q.SignalExportSource(ctx, gen.SignalExportSourceParams{Now: now, Cve: toTextOpt("CVE-2026-1005"), SlaState: toTextOpt("breached")})
	if err != nil {
		t.Fatalf("filter paused clock sla_state breached: %v", err)
	}
	if got := exportRowIDs(pausedBreached); len(got) != 0 {
		t.Fatalf("paused clock sla_state breached = %v, want none", got)
	}
}

// retentionCandidateIDs projects the retention candidate rows onto their id strings.
func retentionCandidateIDs(rows []gen.RiskSignal) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, uuidString(r.ID))
	}
	return out
}

// exportRowIDs projects the export-source rows onto their id strings.
func exportRowIDs(rows []gen.SignalExportSourceRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, uuidString(r.ID))
	}
	return out
}

// sameJSON compares two jsonb payloads semantically — PostgreSQL normalises
// the stored jsonb (key order/spacing), so a byte comparison would be flaky.
func sameJSON(a, b []byte) bool {
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	u, err := toUUID(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return u
}

func mustTime(s string) time.Time {
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return v
}
