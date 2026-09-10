package main

// Integration test of the WP-3.10 epss_history wiring (DEV-053, ARCH-003 §7,
// ADR-012/ADR-013) at the composition root: an EPSS run loads the daily set
// (TRUNCATE + COPY) and, on the same transaction, appends epss_history rows
// for exactly the CVEs with inventory relevance — the candidate pre-filter's
// set — and for no other. The test seeds one component (Acme Portal) and two
// vulnerabilities: CVE-2026-0001 whose affected product meets the component
// (relevant) and CVE-2026-0002 whose product does not (irrelevant), plus a
// third daily-file CVE with no vulnerability row at all. The real EPSS
// adapter runs against an in-process httptest server serving a gzipped daily
// fixture, so the whole path — fetch, TRUNCATE + COPY, reverse pre-filter
// read, CandidateComponentIDs gate, append-only write — is exercised on a
// real short-lived PostgreSQL.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/epss"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// epssHistoryVulnCSV is the daily-file fixture of the test: the relevant
// CVE-2026-0001, the irrelevant CVE-2026-0002 and the untracked
// CVE-2026-0003 (no vulnerability row — never relevant).
const epssHistoryVulnCSV = `#model_version:v2026.03.01,score_date:2026-09-09T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.97368,0.9991
CVE-2026-0002,0.00510,0.4021
CVE-2026-0003,0.31000,0.8800
`

// historyConfig renders the NVD API 2.0 configurations block of one affected
// CPE.
func historyConfig(criteria string) []byte {
	return []byte(`[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"` + criteria + `"}]}]}]`)
}

// TestEpssRunAppendsHistoryForRelevantCVEsOnly drives the DEV-053 acceptance
// criterion: the EPSS run appends history for the relevant CVE only.
func TestEpssRunAppendsHistoryForRelevantCVEsOnly(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)
	q := gen.New(pool)
	at := mustTS(t, "2026-09-09T09:30:00Z")

	// Inventory: one asset with one Acme Portal component (the I3 write
	// path; the natural key derived like the demo seed).
	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID:  "asset-epss-history",
		Source:      "demo",
		Type:        "server_vm",
		Name:        "History Portal",
		Environment: "production",
		Criticality: "critical",
		Exposure:    "internet",
		Owner:       pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	vendorNorm, productNorm, naturalKey, err := seededComponentKey("Acme", "Portal", "2.4")
	if err != nil {
		t.Fatalf("seededComponentKey: %v", err)
	}
	if _, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID:       assetID,
		Vendor:        "Acme",
		Product:       "Portal",
		Version:       "2.4",
		VendorNorm:    vendorNorm,
		ProductNorm:   productNorm,
		VersionScheme: "unknown",
		NaturalKey:    naturalKey,
		UpdatedAt:     at,
	}); err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}

	// Two vulnerabilities: one whose affected product meets the component
	// (the relevant CVE), one whose product meets nothing (the irrelevant
	// CVE). Both have a vulnerability row, so relevance — not existence —
	// is what decides the history append.
	if _, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       "CVE-2026-0001",
		Summary:     "Portal remote code execution",
		PublishedAt: at,
		ModifiedAt:  at,
		CpeConfig:   historyConfig("cpe:2.3:a:acme:portal:2.4:*:*:*:*:*:*:*"),
	}); err != nil {
		t.Fatalf("UpsertVulnerability (relevant): %v", err)
	}
	if _, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       "CVE-2026-0002",
		Summary:     "Unrelated library flaw",
		PublishedAt: at,
		ModifiedAt:  at,
		CpeConfig:   historyConfig("cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*"),
	}); err != nil {
		t.Fatalf("UpsertVulnerability (irrelevant): %v", err)
	}

	// The EPSS source and its daily-file server.
	day := gzipFixture(t, epssHistoryVulnCSV)
	srv := epssFileServer(t, day, day)
	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "epss",
		Name:     "epss-history-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@daily", Valid: true},
		Enabled:  true,
		Config:   []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	svc := newSourceRunService(pool, clk)
	adapter := epss.New(srv.Client().Transport, clk)

	// --- run: the daily set swaps and the relevant-only history appends ---
	res, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: demoUUID(sourceID), Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource: %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Counters.Normalized != 3 {
		t.Fatalf("run result = status %s counters %+v, want succeeded with the 3 daily rows", res.Status, res.Counters)
	}

	// The whole day landed in epss_current (the swap is unfiltered)...
	if count, err := q.CountEpssRows(ctx); err != nil || count != 3 {
		t.Fatalf("epss_current count = %d, %v; want the 3 daily rows", count, err)
	}

	// ... but epss_history holds exactly the relevant CVE, stamped with the
	// run date (observed_on) and the file date (model_version).
	var total int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM epss_history").Scan(&total); err != nil {
		t.Fatalf("count epss_history: %v", err)
	}
	if total != 1 {
		t.Fatalf("epss_history rows = %d, want 1 — relevant-only, no history for the irrelevant/untracked CVEs", total)
	}
	var cveID, modelVersion, observedOn string
	var score, percentile float64
	if err := pool.QueryRow(ctx,
		`SELECT cve_id, model_version, observed_on::text, score::float8, percentile::float8
		 FROM epss_history`).Scan(&cveID, &modelVersion, &observedOn, &score, &percentile); err != nil {
		t.Fatalf("read epss_history row: %v", err)
	}
	if cveID != "CVE-2026-0001" {
		t.Fatalf("epss_history cve_id = %q, want the relevant CVE-2026-0001", cveID)
	}
	if observedOn != "2026-09-09" {
		t.Fatalf("epss_history observed_on = %q, want the run date 2026-09-09", observedOn)
	}
	if modelVersion != "2026-09-09" {
		t.Fatalf("epss_history model_version = %q, want the file date 2026-09-09", modelVersion)
	}
	if score != 0.97368 || percentile != 0.9991 {
		t.Fatalf("epss_history score/percentile = %v/%v, want the daily row's 0.97368/0.9991", score, percentile)
	}

	// The irrelevant CVE (a row exists, its product meets nothing) and the
	// untracked CVE (no row) left no history.
	for _, absent := range []string{"CVE-2026-0002", "CVE-2026-0003"} {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM epss_history WHERE cve_id = $1", absent).Scan(&n); err != nil {
			t.Fatalf("count history of %s: %v", absent, err)
		}
		if n != 0 {
			t.Fatalf("epss_history rows of %s = %d, want 0", absent, n)
		}
	}

	// --- same-day re-fetch: the NoChange no-op appends nothing again ------
	res, err = svc.RunSource(ctx, application.RunSourceInput{SourceID: demoUUID(sourceID), Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (unchanged re-fetch): %v", err)
	}
	if !res.Meta.NoChange {
		t.Fatalf("unchanged re-fetch = meta %+v, want the NoChange no-op", res.Meta)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM epss_history").Scan(&total); err != nil {
		t.Fatalf("count epss_history after no-op: %v", err)
	}
	if total != 1 {
		t.Fatalf("epss_history rows after the no-op = %d, want 1 — the append is per (cve_id, observed_on)", total)
	}
}
