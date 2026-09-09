package main

// Integration test of the WP-1b.02 core schema + sqlc queries (DEV-016) at
// the composition root. cmd/risksignal is the composition root that may wire
// the embedded migration set (db/migrations) together with the postgres
// adapter (the architecture gate keeps db/migrations out of
// internal/adapters/** — `make lint-arch` enforces that), so the schema and
// query round trip is exercised here.
//
// The test drives the exit criteria of WP-1b.02 on a real, short-lived
// PostgreSQL: a fresh database migrates cleanly with the embedded set and a
// second run is a no-op (ADR-010 checksum log intact), then a signal row
// travels the whole generated data path — seed (source, asset, component),
// ingest (source run, raw record, vulnerability, evidence), match and
// signal — and comes back through the generated read path (GetSignalByID,
// GetSignalByMatchID, ListSignals). Idempotent re-runs of the natural-key
// writes stay duplicate-free, which is the groundwork for `demo seed` /
// `demo run` (WP-1b.05).
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/xpera/risksignal/internal/domain"
)

// mustTS parses an RFC 3339 timestamp as the pgx timestamptz of the fixed
// test clock — the data path never reads the wall clock (ch. 7.2).
func mustTS(t *testing.T, s string) pgtype.Timestamptz {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse test timestamp %q: %v", s, err)
	}
	return pgtype.Timestamptz{Time: parsed, Valid: true}
}

// testHash returns a 64-char hex string (the shape of a SHA-256 hex value);
// the database does not verify the digest, only its presence.
func testHash(seed byte) string {
	return strings.Repeat(string([]byte{seed}), 64)
}

// testFactors is the contributing-factors payload of the signal (ARCH-001
// §1 risk_signals.factors: confidence, method, cvss, kev, epss, criticality,
// exposure).
var testFactors = []byte(`{
	"confidence": "high",
	"method": "exact_identifier",
	"cvss": 9.8,
	"kev": true,
	"epss": 0.99,
	"criticality": "critical",
	"exposure": "internet"
}`)

func TestCoreSchemaMigratesAndSignalRoundTripThroughGeneratedQueries(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Exit criterion 1 (WP-1b.02): a fresh database migrates cleanly with
	// the full embedded set and a second run is a no-op (checksum log
	// intact, ADR-010).
	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("fresh migrate: %v", err)
	}
	want := embeddedVersions(t)
	if len(res.Applied) != len(want) {
		t.Fatalf("fresh migrate applied %d migration(s), want the full embedded set %v", len(res.Applied), want)
	}
	for i, v := range want {
		if res.Applied[i].Version != v {
			t.Fatalf("fresh migrate applied %+v, want versions %v in order", res.Applied, want)
		}
	}
	res, err = runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("rerun migrate: %v", err)
	}
	if len(res.Applied) != 0 || len(res.Recovered) != 0 || res.Verified != len(want) {
		t.Fatalf("rerun result = %+v, want no applied/recovered migrations and %d verified", res, len(want))
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)
	q := gen.New(pool)

	started := mustTS(t, "2026-09-09T09:00:00Z")
	fetched := mustTS(t, "2026-09-09T09:00:05Z")
	published := mustTS(t, "2024-01-15T00:00:00Z")
	modified := mustTS(t, "2026-09-01T00:00:00Z")

	// --- seed path (WP-1b.05 groundwork) ---------------------------------
	// Source registration and inventory assets/components; the natural-key
	// writes are idempotent (seeding twice yields no duplicates).
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type: "synthetic", Name: "synthetic-source", Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID: "asset-portal", Source: "demo", Type: "server_vm",
		Name: "Portal", Environment: "production", Criticality: "critical",
		Exposure: "internet", Owner: pgtype.Text{String: "ops", Valid: true},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	if again, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID: "asset-portal", Source: "demo", Type: "server_vm",
		Name: "Portal", Environment: "production", Criticality: "critical",
		Exposure: "internet", Owner: pgtype.Text{String: "ops", Valid: true},
	}); err != nil || again != assetID {
		t.Fatalf("UpsertAsset rerun = %v, %v; want the same asset id", again, err)
	}
	// The I3 write path (WP-3.03a / DEV-056): the seeded component row
	// supplies the normalised comparison keys, the 'unknown' scheme and the
	// domain-derived natural key (seededComponentKey →
	// domain.ComponentNaturalKey), so the insert participates in the
	// product index and the UQ (asset_id, natural_key) idempotency key.
	vendorNorm, productNorm, naturalKey, err := seededComponentKey("acme", "portal", "2.4")
	if err != nil {
		t.Fatalf("seededComponentKey: %v", err)
	}
	componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID:       assetID,
		Vendor:        "acme",
		Product:       "portal",
		Version:       "2.4",
		VendorNorm:    vendorNorm,
		ProductNorm:   productNorm,
		VersionScheme: string(domain.VersionSchemeUnknown),
		NaturalKey:    naturalKey,
		UpdatedAt:     mustTS(t, "2026-09-09T08:00:00Z"),
	})
	if err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}
	components, err := q.ListComponentsByVendorProduct(ctx, gen.ListComponentsByVendorProductParams{
		Vendor: "acme", Product: "portal",
	})
	if err != nil || len(components) != 1 || components[0].ID != componentID {
		t.Fatalf("ListComponentsByVendorProduct = %+v, %v; want exactly the seeded component", components, err)
	}
	source, err := q.GetSourceByTypeAndName(ctx, gen.GetSourceByTypeAndNameParams{
		Type: "synthetic", Name: "synthetic-source",
	})
	if err != nil || source.ID != sourceID || !source.Enabled {
		t.Fatalf("GetSourceByTypeAndName = %+v, %v; want the registered source, enabled", source, err)
	}

	// --- ingest path (ARCH-001 §3 steps 1-3) ------------------------------
	// Source run, raw record (idempotent), vulnerability (idempotent
	// upsert) and one synthetic-statement evidence.
	run, err := q.CreateSourceRun(ctx, gen.CreateSourceRunParams{SourceID: sourceID, StartedAt: started})
	if err != nil {
		t.Fatalf("CreateSourceRun: %v", err)
	}
	if run.Status != "running" || string(run.Counters) != "{}" {
		t.Fatalf("CreateSourceRun = %+v, want status running and empty counters", run)
	}

	rawPayload := []byte(`{"document": "synthetic-reference", "run": 1}`)
	rawID, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "synthetic-reference",
		ContentHash: testHash('a'), Payload: rawPayload, FetchedAt: fetched,
	})
	if err != nil {
		t.Fatalf("InsertRawRecord: %v", err)
	}
	if again, err := q.InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID: sourceID, ExternalID: "synthetic-reference",
		ContentHash: testHash('a'), Payload: rawPayload, FetchedAt: fetched,
	}); err != nil || again != rawID {
		t.Fatalf("InsertRawRecord rerun = %v, %v; want the same raw record id", again, err)
	}

	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: "CVE-2024-0001", Summary: "Demo remote code execution",
		PublishedAt: published, ModifiedAt: modified,
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}
	if again, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: "CVE-2024-0001", Summary: "Demo remote code execution",
		PublishedAt: published, ModifiedAt: modified,
	}); err != nil || again != vulnID {
		t.Fatalf("UpsertVulnerability rerun = %v, %v; want the same vulnerability id", again, err)
	}

	evidenceValue := []byte(`{"statement": "acme/portal 2.4 is affected by CVE-2024-0001"}`)
	evidenceParams := gen.InsertEvidenceParams{
		VulnerabilityID: vulnID, RawRecordID: rawID, Type: "synthetic_statement",
		Value: evidenceValue, ValueHash: testHash('e'), ObservedAt: fetched,
	}
	evidenceID, err := q.InsertEvidence(ctx, evidenceParams)
	if err != nil {
		t.Fatalf("InsertEvidence: %v", err)
	}
	// A repeated statement is a no-op on the natural key and returns the
	// already existing id (ARCH-003 §7: AddEvidence returns the
	// new-or-existing evidence id) — the double insert must stay a single
	// row.
	againEvidenceID, err := q.InsertEvidence(ctx, evidenceParams)
	if err != nil || againEvidenceID != evidenceID {
		t.Fatalf("InsertEvidence rerun = %v, %v; want the same evidence id %v", againEvidenceID, err, evidenceID)
	}
	var evidenceCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM evidences").Scan(&evidenceCount); err != nil {
		t.Fatalf("count evidences: %v", err)
	}
	if evidenceCount != 1 {
		t.Fatalf("evidences after double insert = %d, want 1 (natural-key idempotency)", evidenceCount)
	}

	// --- match path (ARCH-001 §3 step 4, ADR-015) --------------------------
	// reasons is a jsonb NOT NULL column (default '[]'); the gen-level write
	// passes the purely-computed default explicitly (the repository layer
	// does the same for application.MatchRecord).
	matchID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID, ComponentID: componentID, Method: "exact_identifier",
		Score: 100, Confidence: "high", RuleVersion: "i1b-1", CreatedAt: fetched,
		Reasons: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("InsertMatch: %v", err)
	}
	if again, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID, ComponentID: componentID, Method: "exact_identifier",
		Score: 100, Confidence: "high", RuleVersion: "i1b-1", CreatedAt: fetched,
		Reasons: []byte("[]"),
	}); err != nil || again != matchID {
		t.Fatalf("InsertMatch rerun = %v, %v; want the same match id", again, err)
	}

	// --- signal path: write (ARCH-001 §3 step 5) --------------------------
	// status ('new') and version (1) come from the column defaults; the
	// duplicate insert on the same match must be rejected by UQ (match_id).
	signal, err := q.InsertRiskSignal(ctx, gen.InsertRiskSignalParams{
		MatchID: matchID, Priority: "P1", RuleVersion: "i1b-1",
		Factors: testFactors, CreatedAt: fetched,
	})
	if err != nil {
		t.Fatalf("InsertRiskSignal: %v", err)
	}
	if signal.Status != "new" || signal.Version != 1 {
		t.Fatalf("InsertRiskSignal = %+v, want defaults status new and version 1", signal)
	}
	if _, err := q.InsertRiskSignal(ctx, gen.InsertRiskSignalParams{
		MatchID: matchID, Priority: "P1", RuleVersion: "i1b-1",
		Factors: testFactors, CreatedAt: fetched,
	}); err == nil {
		t.Fatal("second InsertRiskSignal on the same match: expected a unique-violation error")
	}

	// Complete the source run (counters advance only on success, ch. 6.1).
	counters := []byte(`{"records": 1, "matched": 1, "signals": 1}`)
	done, err := q.CompleteSourceRun(ctx, gen.CompleteSourceRunParams{
		ID: run.ID, FinishedAt: mustTS(t, "2026-09-09T09:00:10Z"),
		Status: "succeeded", Counters: counters, Error: pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("CompleteSourceRun: %v", err)
	}
	if done.Status != "succeeded" {
		t.Fatalf("CompleteSourceRun status = %q, want succeeded", done.Status)
	}
	var countersMap map[string]int
	if err := json.Unmarshal(done.Counters, &countersMap); err != nil {
		t.Fatalf("decode run counters: %v", err)
	}
	if countersMap["records"] != 1 || countersMap["matched"] != 1 || countersMap["signals"] != 1 {
		t.Fatalf("run counters = %v, want records/matched/signals = 1", countersMap)
	}

	// --- signal path: reads (ARCH-001 §4) ---------------------------------
	byMatch, err := q.GetSignalByMatchID(ctx, matchID)
	if err != nil || byMatch != signal.ID {
		t.Fatalf("GetSignalByMatchID = %v, %v; want the inserted signal id", byMatch, err)
	}

	detail, err := q.GetSignalByID(ctx, signal.ID)
	if err != nil {
		t.Fatalf("GetSignalByID: %v", err)
	}
	if detail.ID != signal.ID || detail.MatchID != matchID {
		t.Fatalf("detail ids = %v/%v, want %v/%v", detail.ID, detail.MatchID, signal.ID, matchID)
	}
	if detail.Priority != "P1" || detail.Status != "new" || detail.Version != 1 || detail.RuleVersion != "i1b-1" {
		t.Fatalf("detail signal fields = %+v, want P1/new/version 1/i1b-1", detail)
	}
	if detail.CveID != "CVE-2024-0001" || detail.Summary != "Demo remote code execution" {
		t.Fatalf("detail vulnerability = %s/%s, want CVE-2024-0001 with the summary", detail.CveID, detail.Summary)
	}
	if detail.Method != "exact_identifier" || detail.Confidence != "high" {
		t.Fatalf("detail match = %s/%s, want exact_identifier/high", detail.Method, detail.Confidence)
	}
	if detail.Vendor != "acme" || detail.Product != "portal" || detail.ComponentVersion != "2.4" {
		t.Fatalf("detail component = %s/%s/%s, want acme/portal/2.4", detail.Vendor, detail.Product, detail.ComponentVersion)
	}
	if detail.AssetID != assetID || detail.AssetExternalID != "asset-portal" || detail.AssetType != "server_vm" ||
		detail.AssetName != "Portal" || detail.AssetCriticality != "critical" || detail.AssetExposure != "internet" {
		t.Fatalf("detail asset = %+v, want the seeded portal asset", detail)
	}
	var gotFactors map[string]any
	if err := json.Unmarshal(detail.Factors, &gotFactors); err != nil {
		t.Fatalf("decode signal factors: %v", err)
	}
	var wantFactors map[string]any
	if err := json.Unmarshal(testFactors, &wantFactors); err != nil {
		t.Fatalf("decode expected factors: %v", err)
	}
	if !reflect.DeepEqual(gotFactors, wantFactors) {
		t.Fatalf("signal factors = %v, want %v", gotFactors, wantFactors)
	}

	// The working list honours the optional filters and the P1→P4 order.
	list, err := q.ListSignals(ctx, gen.ListSignalsParams{MaxRows: 10})
	if err != nil || len(list) != 1 || list[0].ID != signal.ID {
		t.Fatalf("ListSignals = %+v, %v; want exactly the inserted signal", list, err)
	}
	filtered, err := q.ListSignals(ctx, gen.ListSignalsParams{
		Priority: pgtype.Text{String: "P1", Valid: true}, Status: pgtype.Text{String: "new", Valid: true},
		MaxRows: 10,
	})
	if err != nil || len(filtered) != 1 || filtered[0].ID != signal.ID {
		t.Fatalf("ListSignals(P1, new) = %+v, %v; want exactly the inserted signal", filtered, err)
	}
	filtered, err = q.ListSignals(ctx, gen.ListSignalsParams{
		Priority: pgtype.Text{String: "P2", Valid: true}, MaxRows: 10,
	})
	if err != nil || len(filtered) != 0 {
		t.Fatalf("ListSignals(P2) = %+v, %v; want no rows", filtered, err)
	}
}
