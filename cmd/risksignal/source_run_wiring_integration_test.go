package main

// Integration tests of the DEV-041 source-run wiring (ARCH-002 §1/§2.2/§2.3,
// §5) at the composition root: the full RunSource cycle of the real KEV and
// EPSS adapters against a real, short-lived PostgreSQL, with the adapter
// endpoints pointed at in-process httptest servers serving versioned
// fixtures (ARCH-002 §6: network-free).
//
// The three deferred inputs of the WP-2.06/2.07 review findings are proven
// end-to-end:
//
//  1. EPSS bulk load — RunSource fetches the daily gzip file, the normalise
//     pass streams the parsed rows into the BulkRowWriter and the set lands
//     in epss_current through the TRUNCATE + COPY swap of the run
//     transaction (atomic: the row count matches the fixture, model_version
//     and loaded_at are stamped). Re-running the same day's unchanged file
//     is a NoChange no-op (counters all 0, set untouched), and a later day
//     replaces the set atomically — no residue of the previous day.
//  2. KEV removal historisation — a second, changed catalog run receives
//     the previous catalog's CVE set (NormalizeInput.PreviousKEVCVEs) and
//     emits the kev_removed evidence for the dropped entry; an unchanged
//     re-run of that catalog is a NoChange no-op that re-historises
//     nothing.
//  3. last_content_hash + FetchedAt — after every committed fetch the
//     source config holds the fetched content hash (the NoChange detection
//     of the re-runs above reads it) and the stored raw records carry the
//     run's clock instant instead of the zero time.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/adapters/sources/epss"
	"github.com/xpera/risksignal/internal/adapters/sources/kev"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// sourceRunClockStart is the fixed instant the wiring tests start their
// injected clock at (the 2026-09-09 daily EPSS file date).
var sourceRunClockStart = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)

// newSourceRunService wires the application service for the source-run
// integration tests exactly as the production composition roots do (same
// wiring as newCreateSignalService — all real postgres repositories,
// postgres.WithTx as the transaction boundary) with the injected clock as
// the time source.
func newSourceRunService(pool *pgxpool.Pool, clk clock.Clock) *application.Service {
	q := gen.New(pool)
	epssHistory, err := application.NewEpssHistoryLoader(
		repo.NewRuleRepo(q), repo.NewComponentRepo(q), repo.NewVulnerabilityMatchRepo(q), repo.NewEpssHistoryRepo(q))
	if err != nil {
		panic("configure epss history loader: " + err.Error())
	}
	return application.NewService(application.ServiceDeps{
		Signals:         repo.NewSignalRepo(q),
		Audit:           repo.NewAuditRepo(q),
		Outbox:          repo.NewOutboxRepo(q),
		Vulnerabilities: repo.NewVulnerabilityRepo(q),
		Matches:         repo.NewMatchRepo(q),
		SourceRuns:      repo.NewSourceRunRepo(q),
		RawRecords:      repo.NewRawRecordRepo(q),
		Sources:         repo.NewSourceRepo(q),
		Quarantine:      repo.NewQuarantineRepo(q),
		Components:      repo.NewComponentRepo(q),
		Inventory:       repo.NewInventoryRepo(q),
		EpssHistory:     epssHistory,
		Clock:           clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
}

// gzipFixture compresses a daily-file CSV into the gzip payload shape the
// EPSS fetch stores and the normaliser decompresses.
func gzipFixture(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(text)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// sha256Hex is the SHA-256 hex digest of b — the expected ContentHash.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// EPSS: daily-set bulk load, NoChange no-op, atomic replacement

// epssDay1CSV and epssDay2CSV are two daily-set fixtures (shape of the real
// FIRST file: comment line, header, plain data rows). Day two shares one CVE
// with day one and drops the other two — a smaller, different set.
const (
	epssDay1CSV = `#model_version:v2026.03.01,score_date:2026-09-09T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.97368,0.9991
CVE-2026-0002,0.00510,0.4021
CVE-2026-0003,0.00057,0.1937
`
	epssDay2CSV = `#model_version:v2026.03.02,score_date:2026-09-10T00:00:00+0000
cve,epss,percentile
CVE-2026-0001,0.98200,0.9995
CVE-2026-0009,0.31000,0.8800
`
)

// epssFileServer serves the daily files of the two fixture days under their
// canonical names (epss_scores-YYYY-MM-DD.csv.gz); any other file is a 404.
func epssFileServer(t *testing.T, day1, day2 []byte) *httptest.Server {
	t.Helper()
	files := map[string][]byte{
		"epss_scores-2026-09-09.csv.gz": day1,
		"epss_scores-2026-09-10.csv.gz": day2,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		body, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 04:00:00 GMT")
		if _, err := w.Write(body); err != nil {
			t.Fatalf("serve %s: %v", name, err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sourceConfigHash reads the source's stored config.last_content_hash.
func sourceConfigHash(t *testing.T, pool *pgxpool.Pool, sourceID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var hash pgtype.Text
	if err := pool.QueryRow(ctx,
		"SELECT config->>'last_content_hash' FROM sources WHERE id = $1", mustUUID(t, sourceID)).Scan(&hash); err != nil {
		t.Fatalf("read source config hash: %v", err)
	}
	return hash.String
}

// countRawRecords returns the raw record census of one source.
func countRawRecords(t *testing.T, pool *pgxpool.Pool, sourceID string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM raw_records WHERE source_id = $1", mustUUID(t, sourceID)).Scan(&n); err != nil {
		t.Fatalf("count raw records: %v", err)
	}
	return n
}

// TestSourceRunWiringEpssBulkLoadNoOpAndReplacement drives the whole EPSS
// path through RunSource: the daily set is loaded with the run (TRUNCATE +
// COPY, row count in the counters), the unchanged re-fetch of the same day
// is a NoChange no-op (last_content_hash), and the next day's file replaces
// the set atomically.
func TestSourceRunWiringEpssBulkLoadNoOpAndReplacement(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	day1 := gzipFixture(t, epssDay1CSV)
	day2 := gzipFixture(t, epssDay2CSV)
	srv := epssFileServer(t, day1, day2)
	q := gen.New(pool)

	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "epss",
		Name:     "epss-wiring-int",
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

	// --- run 1: the 2026-09-09 daily set is loaded with the run -----------
	res, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: demoUUID(sourceID), Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (day one): %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("day-one status = %s, want succeeded", res.Status)
	}
	if res.Counters.Records != 1 || res.Counters.Normalized != 3 || res.Counters.Errors != 0 {
		t.Fatalf("day-one counters = %+v, want records 1 normalized 3 (the fixture row count)", res.Counters)
	}

	// The set holds exactly the three fixture rows; the stamped metadata
	// carries the file date and the run's clock instant.
	count, err := q.CountEpssRows(ctx)
	if err != nil || count != 3 {
		t.Fatalf("epss_current count = %d, %v; want the 3 fixture rows", count, err)
	}
	row, err := q.GetEpssByCveID(ctx, "CVE-2026-0002")
	if err != nil {
		t.Fatalf("GetEpssByCveID(CVE-2026-0002): %v", err)
	}
	if row.ModelVersion != "2026-09-09" || !row.LoadedAt.Time.Equal(sourceRunClockStart) {
		t.Fatalf("day-one row meta = %q / %v, want model 2026-09-09 loaded at the run's clock %v", row.ModelVersion, row.LoadedAt.Time, sourceRunClockStart)
	}

	// The committed fetch maintained last_content_hash and stamped the raw
	// record's fetched_at with the run's clock instant.
	if got := sourceConfigHash(t, pool, demoUUID(sourceID)); got != sha256Hex(day1) {
		t.Fatalf("config last_content_hash = %q, want the day-one file hash", got)
	}
	var fetchedAt time.Time
	if err := pool.QueryRow(ctx,
		"SELECT fetched_at FROM raw_records WHERE source_id = $1", sourceID).Scan(&fetchedAt); err != nil {
		t.Fatalf("read raw record fetched_at: %v", err)
	}
	assertUTCTimestamp(t, "day-one raw record fetched_at", fetchedAt, sourceRunClockStart)

	// --- run 2: the same day's unchanged file is a NoChange no-op ---------
	res, err = svc.RunSource(ctx, application.RunSourceInput{SourceID: demoUUID(sourceID), Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (unchanged re-run): %v", err)
	}
	if !res.Meta.NoChange || res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("unchanged re-run = status %s meta %+v, want the successful no-op (Meta.NoChange)", res.Status, res.Meta)
	}
	if res.Counters.Records != 0 || res.Counters.Normalized != 0 {
		t.Fatalf("no-op counters = %+v, want all 0", res.Counters)
	}
	if count, err := q.CountEpssRows(ctx); err != nil || count != 3 {
		t.Fatalf("epss_current count after no-op = %d, %v; want 3 — the set is untouched", count, err)
	}
	if n := countRawRecords(t, pool, demoUUID(sourceID)); n != 1 {
		t.Fatalf("raw records after no-op = %d, want 1 — nothing stored", n)
	}
	if got := sourceConfigHash(t, pool, demoUUID(sourceID)); got != sha256Hex(day1) {
		t.Fatalf("config hash after no-op = %q, want the unchanged day-one hash", got)
	}

	// --- run 3: the next day's file replaces the set atomically -----------
	clk.Advance(24 * time.Hour)
	res, err = svc.RunSource(ctx, application.RunSourceInput{SourceID: demoUUID(sourceID), Adapter: adapter})
	if err != nil {
		t.Fatalf("RunSource (day two): %v", err)
	}
	if res.Status != application.SourceRunStatusSucceeded || res.Counters.Normalized != 2 {
		t.Fatalf("day-two result = status %s counters %+v, want succeeded with normalized 2", res.Status, res.Counters)
	}
	count, err = q.CountEpssRows(ctx)
	if err != nil || count != 2 {
		t.Fatalf("epss_current count after day two = %d, %v; want 2 (set replaced, no residue)", count, err)
	}
	row, err = q.GetEpssByCveID(ctx, "CVE-2026-0009")
	if err != nil {
		t.Fatalf("GetEpssByCveID(CVE-2026-0009): %v", err)
	}
	if row.ModelVersion != "2026-09-10" || !row.LoadedAt.Time.Equal(sourceRunClockStart.Add(24*time.Hour)) {
		t.Fatalf("day-two row meta = %q / %v, want model 2026-09-10 loaded at the advanced clock", row.ModelVersion, row.LoadedAt.Time)
	}
	if _, err := q.GetEpssByCveID(ctx, "CVE-2026-0002"); err == nil {
		t.Fatal("day-one-only CVE still present after day two — the swap must leave no residue")
	}
	if got := sourceConfigHash(t, pool, demoUUID(sourceID)); got != sha256Hex(day2) {
		t.Fatalf("config last_content_hash after day two = %q, want the day-two file hash", got)
	}
	if n := countRawRecords(t, pool, demoUUID(sourceID)); n != 2 {
		t.Fatalf("raw records after day two = %d, want 2", n)
	}
}

// ---------------------------------------------------------------------------
// KEV: removal historisation against the previous catalog, NoChange re-run

// kevEntryJSON renders one catalog entry for the given CVE.
func kevEntryJSON(cve string) string {
	return fmt.Sprintf(`{
	  "cveID": %q,
	  "vendorProject": "Acme",
	  "product": "Widget",
	  "vulnerabilityName": "Acme Widget Command Injection",
	  "dateAdded": "2026-08-01",
	  "shortDescription": "Command injection in the Acme Widget allows remote takeover.",
	  "requiredAction": "Apply vendor-supplied mitigations.",
	  "dueDate": "2026-11-01",
	  "knownRansomwareCampaignUse": false
	}`, cve)
}

// kevCatalogJSON renders one catalog document envelope (the metadata the
// fetch's external id derives from: kev-<dateReleased date>).
func kevCatalogJSON(dateReleased string, cves ...string) string {
	entries := make([]string, 0, len(cves))
	for _, cve := range cves {
		entries = append(entries, kevEntryJSON(cve))
	}
	return `{"title":"CISA Catalog of Known Exploited Vulnerabilities",` +
		`"catalogVersion":"2026.09.09",` +
		`"dateReleased":"` + dateReleased + `",` +
		`"count":` + fmt.Sprintf("%d", len(cves)) + `,` +
		`"vulnerabilities":[` + strings.Join(entries, ",") + `]}`
}

// countEvidenceRows returns the evidence census of one type.
func countEvidenceRows(t *testing.T, pool *pgxpool.Pool, typ string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var n int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM evidences WHERE type = $1", typ).Scan(&n); err != nil {
		t.Fatalf("count %s evidence rows: %v", typ, err)
	}
	return n
}

// TestSourceRunWiringKevHistorisesRemovalsAndNoChangeReRun drives the KEV
// path through RunSource: catalog v1 loads three skeletons with kev
// evidences, catalog v2 (one entry dropped) receives the previous set and
// historises the removal as a kev_removed evidence, and the unchanged v2
// re-fetch is a NoChange no-op that neither stores nor re-historises.
func TestSourceRunWiringKevHistorisesRemovalsAndNoChangeReRun(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clk := clock.NewFakeClock(sourceRunClockStart)

	// The server serves whichever catalog revision the test points at.
	catalogV1 := kevCatalogJSON("2026-09-09T04:00:00.000Z", "CVE-2026-0101", "CVE-2026-0102", "CVE-2026-0103")
	catalogV2 := kevCatalogJSON("2026-09-10T04:00:00.000Z", "CVE-2026-0101", "CVE-2026-0102")
	current := catalogV1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 04:00:00 GMT")
		if _, err := w.Write([]byte(current)); err != nil {
			t.Fatalf("serve catalog: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	q := gen.New(pool)

	sourceID, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     "kev",
		Name:     "kev-wiring-int",
		Endpoint: pgtype.Text{String: srv.URL, Valid: true},
		Schedule: pgtype.Text{String: "@daily", Valid: true},
		Enabled:  true,
		Config:   []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("UpsertSource: %v", err)
	}
	svc := newSourceRunService(pool, clk)
	adapter := kev.New(srv.Client().Transport)
	run := func() application.RunSourceResult {
		t.Helper()
		res, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: demoUUID(sourceID), Adapter: adapter})
		if err != nil {
			t.Fatalf("RunSource: %v", err)
		}
		return res
	}

	// --- run 1: catalog v1 loads three skeletons + kev evidences ----------
	res := run()
	if res.Status != application.SourceRunStatusSucceeded || res.Counters.Records != 1 {
		t.Fatalf("v1 result = status %s counters %+v, want succeeded with the raw record stored", res.Status, res.Counters)
	}
	if got := countEvidenceRows(t, pool, "kev"); got != 3 {
		t.Fatalf("kev evidence rows after v1 = %d, want 3", got)
	}
	if got := countEvidenceRows(t, pool, "kev_removed"); got != 0 {
		t.Fatalf("kev_removed rows after v1 = %d, want 0 (first import)", got)
	}
	if got := sourceConfigHash(t, pool, demoUUID(sourceID)); got != sha256Hex([]byte(catalogV1)) {
		t.Fatalf("config hash after v1 = %q, want the v1 catalog hash", got)
	}

	// --- run 2: catalog v2 drops CVE-2026-0103; the removal is historised -
	clk.Advance(24 * time.Hour)
	current = catalogV2
	res = run()
	if res.Status != application.SourceRunStatusSucceeded || res.Counters.Errors != 0 {
		t.Fatalf("v2 result = status %s counters %+v, want succeeded without isolated errors", res.Status, res.Counters)
	}
	if got := countEvidenceRows(t, pool, "kev_removed"); got != 1 {
		t.Fatalf("kev_removed rows after v2 = %d, want 1 — the dropped CVE is historised", got)
	}
	// The removal statement names the dropped entry and is attributed to
	// the v2 raw record.
	var removedCve string
	var removedRaw pgtype.Text
	if err := pool.QueryRow(ctx, `SELECT value->>'cve_id', raw_record_id::text
	                              FROM evidences WHERE type = 'kev_removed'`).Scan(&removedCve, &removedRaw); err != nil {
		t.Fatalf("read kev_removed row: %v", err)
	}
	if removedCve != "CVE-2026-0103" {
		t.Fatalf("kev_removed cve_id = %q, want the dropped CVE-2026-0103", removedCve)
	}
	if got := countEvidenceRows(t, pool, "kev"); got != 5 {
		t.Fatalf("kev evidence rows after v2 = %d, want 5 (3 of v1 + 2 of v2)", got)
	}
	if got := sourceConfigHash(t, pool, demoUUID(sourceID)); got != sha256Hex([]byte(catalogV2)) {
		t.Fatalf("config hash after v2 = %q, want the v2 catalog hash", got)
	}

	// --- run 3: the unchanged v2 catalog is a NoChange no-op --------------
	clk.Advance(24 * time.Hour)
	res = run()
	if !res.Meta.NoChange || res.Status != application.SourceRunStatusSucceeded {
		t.Fatalf("v2 re-run = status %s meta %+v, want the successful no-op (Meta.NoChange)", res.Status, res.Meta)
	}
	if res.Counters.Records != 0 || res.Counters.Normalized != 0 {
		t.Fatalf("no-op counters = %+v, want all 0", res.Counters)
	}
	if n := countRawRecords(t, pool, demoUUID(sourceID)); n != 2 {
		t.Fatalf("raw records after no-op = %d, want 2 — nothing stored", n)
	}
	if got := countEvidenceRows(t, pool, "kev_removed"); got != 1 {
		t.Fatalf("kev_removed rows after no-op = %d, want 1 — the no-op re-historises nothing", got)
	}
}
