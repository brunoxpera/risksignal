// Command perf runs the AT-013 performance harness of iteration I6
// (ARCH-007 §6/§17.1, NFR-003/NFR-004, §17.2 test data strategy).
//
// It deterministically generates a reference volume (250 000 CVEs and
// 10 000 assets by default), loads the CVEs through the real NVD
// full-import path (the checkpointed DEV-067 window walk against an
// in-process, network-free fake NVD server) and deterministically seeds
// the expected hit set (one match + signal per relevant CVE, §17.2: the
// performance data carries expected object and hit sets). It then runs and
// measures the three AT-013 quantities:
//
//   - (a) reference list-query latency p95 (the §10.4 signal filter read,
//     NFR-003: 95 % of the reference queries answer in ≤ 2 s at the
//     reference volume);
//   - (b) incremental source-run duration (the incremental NVD run over a
//     daily delta, NFR-004: processed within 15 minutes after the fetch);
//   - (c) the job count produced by the bulk import (§17.1: a run over the
//     reference volume must not create a job count in the order of
//     magnitude of the CVE count — the full import fans in exactly one
//     matching.rebuild job, ADR-012).
//
// The result is written as a versioned report artifact
// (dist/perf/<version>.md, or dist/perf/<version>-<profile>.md for a
// non-default profile) with every measurement and an explicit pass/fail
// against the thresholds. Re-run it at every relevant persistence change:
// the report is the AT-013 acceptance evidence.
//
// Determinism and scale (§17.2): the whole harness is deterministic — the
// dataset is a pure function of the profile's integer sizes, the clock is
// an injected fake clock at a fixed instant and the only network surface
// is an in-process httptest server (loopback, no live dependency). Because
// the full 250 k run is slow, PERF_SCALE selects the profile: `full` is
// the reference profile and the report source, `smoke` is the reduced but
// structurally identical profile for a quick CI check. The report records
// the profile so a smoke artifact can never be mistaken for the reference
// evidence.
//
// The harness runs against its own scratch database (created, migrated and
// dropped per run) on the PostgreSQL reachable through
// RISKSIGNAL_TEST_DATABASE_URL (the compose db service by default), so it
// never touches the development database and always starts from a clean
// state.
//
// Configuration (environment, all optional):
//
//	PERF_SCALE          full (default) | smoke — the profile
//	PERF_VERSION        version stamped into the report name (default dev)
//	PERF_REPORT_DIR     report directory (default dist/perf)
//	PERF_LIST_ITERATIONS override the profile's list-query iteration count
//	PERF_KEEP_DB=1      keep the scratch database for inspection
//	RISKSIGNAL_TEST_DATABASE_URL  admin connection for the scratch database
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/nvd"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// AT-013 thresholds (§17.1, NFR-003/NFR-004).
const (
	// listP95Threshold is NFR-003: at the reference volume, 95 % of the
	// reference list queries answer in ≤ 2 s.
	listP95Threshold = 2 * time.Second
	// incrementalThreshold is NFR-004: an incremental source run (the
	// daily reference run) is processed within 15 minutes after the fetch.
	incrementalThreshold = 15 * time.Minute
	// jobRatioFactor is the §17.1 job-count bound: the jobs created by the
	// bulk import must stay far below the order of magnitude of the CVE
	// count — jobs*jobRatioFactor ≤ CVE count (one job per 1000 CVEs or
	// fewer; the reference import fans in exactly one matching.rebuild).
	jobRatioFactor = 1000
)

// Profile is one deterministic harness scale. The dataset is a pure
// function of its integers, so the same profile always generates the same
// rows (§17.2).
type Profile struct {
	Name string
	// CVEs is the generated CVE count (the reference profile: 250 000).
	CVEs int
	// Assets is the generated asset count (one component per asset); the
	// reference profile: 10 000.
	Assets int
	// CVERelevance is the hit-set stride: every CVERelevance-th CVE is a
	// relevant hit against one asset's component (the §17.2 expected hit
	// set). It must divide the relevant range cleanly for a stable set.
	CVERelevance int
	// IncrementalCVEs is the daily-delta size of the incremental run: the
	// number of changed CVEs the incremental NVD run fetches (NFR-004).
	IncrementalCVEs int
	// ListIterations is the default number of list-query iterations.
	ListIterations int
}

// profiles is the scale knob (PERF_SCALE). `full` is the reference profile
// and the report source; `smoke` is the reduced, structurally identical
// profile for a quick CI smoke run (§17.2: the property is independent of
// the exact size).
var profiles = map[string]Profile{
	"full": {
		Name:            "full",
		CVEs:            250_000,
		Assets:          10_000,
		CVERelevance:    25, // 10 000 hits, one per asset
		IncrementalCVEs: 5_000,
		ListIterations:  200,
	},
	"smoke": {
		Name:            "smoke",
		CVEs:            5_000,
		Assets:          500,
		CVERelevance:    5, // 1 000 hits, two per asset
		IncrementalCVEs: 100,
		ListIterations:  50,
	},
}

// fixed instants of the harness: the injected fake clock starts here, so
// every timestamp the run writes is a deterministic function of the
// profile (§17.2), independent of the wall clock.
var (
	perfClockStart = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)
	perfSince      = "2026-09-01T00:00:00Z" // the full-import lower bound
)

// defaultAdminURL is the compose db service (compose.yaml); the harness
// creates its scratch database on it.
//
// #nosec G101 -- the loopback-only compose development credential, published
// in compose.yaml; it is not a secret.
const defaultAdminURL = "postgres://risksignal:risksignal@127.0.0.1:5432/risksignal?sslmode=disable"

// scratchDB is the name of the per-run database (dropped and recreated at
// the start, dropped again at the end unless PERF_KEEP_DB=1).
const scratchDB = "risksignal_perf"

// measurement is the outcome of one phase the report records.
type measurement struct {
	label     string
	value     string
	threshold string
	pass      bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "perf: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	profileName := envOr("PERF_SCALE", "full")
	profile, ok := profiles[profileName]
	if !ok {
		return fmt.Errorf("unknown PERF_SCALE %q (want full|smoke)", profileName)
	}
	if v := os.Getenv("PERF_LIST_ITERATIONS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("PERF_LIST_ITERATIONS %q: want a positive integer", v)
		}
		profile.ListIterations = n
	}
	version := envOr("PERF_VERSION", "dev")
	reportDir := envOr("PERF_REPORT_DIR", filepath.Join("dist", "perf"))
	adminURL := envOr("RISKSIGNAL_TEST_DATABASE_URL", defaultAdminURL)
	keepDB := os.Getenv("PERF_KEEP_DB") == "1"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	step("profile %s: %d CVEs, %d assets, %d incremental CVEs, %d list iterations",
		profile.Name, profile.CVEs, profile.Assets, profile.IncrementalCVEs, profile.ListIterations)

	// --- 0) fresh scratch database + migrations (clean state) ------------
	scratchURL, cleanup, err := setupDatabase(ctx, adminURL, keepDB)
	if err != nil {
		return err
	}
	defer cleanup()

	pool, err := postgres.OpenPool(ctx, scratchURL)
	if err != nil {
		return fmt.Errorf("open scratch pool: %w", err)
	}
	defer pool.Close()
	q := gen.New(pool)

	// The application service wired exactly like the production
	// composition roots (the source-run path). A system actor is used for
	// the reads, so no identity port is needed (authz is a no-op for a
	// non-user actor, ARCH-005 §6).
	svc, err := newService(pool)
	if err != nil {
		return err
	}

	clk := clock.NewFakeClock(perfClockStart)

	// --- 1) inventory ----------------------------------------------------
	step("seeding %d assets + components ...", profile.Assets)
	if err := seedInventory(ctx, pool, profile.Assets, perfClockStart); err != nil {
		return fmt.Errorf("seed inventory: %w", err)
	}

	// --- 2) bulk import (the reference NVD full import) ------------------
	fake := &fakeNVD{}
	// The full-import profile: h in [1, CVEs], hit stride CVERelevance.
	fake.set(0, profile.CVEs, profile.CVERelevance, profile.Assets)
	srv := httptest.NewServer(http.HandlerFunc(fake.serve))
	defer srv.Close()

	sourceID, err := upsertSource(ctx, q, srv.URL)
	if err != nil {
		return fmt.Errorf("register NVD source: %w", err)
	}
	adapter := nvd.New(srv.Client().Transport)

	step("bulk import: %d CVEs via the NVD full import ...", profile.CVEs)
	bulkStart := time.Now()
	bulkRes, err := svc.FullImportSource(ctx, application.FullImportSourceInput{
		SourceID: sourceID, Adapter: adapter,
	})
	bulkDur := time.Since(bulkStart)
	if err != nil {
		return fmt.Errorf("full import: %w", err)
	}
	if bulkRes.Status != application.SourceRunStatusSucceeded {
		return fmt.Errorf("full import status %s (want succeeded)", bulkRes.Status)
	}

	// --- (c) the bulk-import job count -----------------------------------
	outbox, err := outboxCounts(ctx, pool)
	if err != nil {
		return err
	}
	totalJobs := 0
	for _, n := range outbox {
		totalJobs += n
	}
	rebuildJobs := outbox[application.EventTypeMatchingRebuild]
	jobPass := totalJobs*jobRatioFactor <= profile.CVEs && rebuildJobs <= 1

	// --- 3) expected hit set (§17.2) -------------------------------------
	step("seeding the expected hit set (matches + signals) ...")
	hits, err := seedHitSet(ctx, pool, profile, perfClockStart)
	if err != nil {
		return fmt.Errorf("seed hit set: %w", err)
	}

	// The reference-volume census is read before the incremental delta so
	// the report's dataset section is the reference dataset (§17.1).
	facts, err := readDatasetFacts(ctx, pool)
	if err != nil {
		return err
	}

	// --- (b) the incremental source run ----------------------------------
	step("incremental run: %d changed CVEs ...", profile.IncrementalCVEs)
	// The daily delta is served as a fresh window past the full import:
	// new CVE ids, every record a relevant change (a real NVD day).
	fake.set(profile.CVEs, profile.IncrementalCVEs, 1, profile.Assets)
	clk.Advance(24 * time.Hour)
	incStart := time.Now()
	incRes, err := svc.RunSource(ctx, application.RunSourceInput{SourceID: sourceID, Adapter: adapter})
	incDur := time.Since(incStart)
	if err != nil {
		return fmt.Errorf("incremental run: %w", err)
	}
	if incRes.Status != application.SourceRunStatusSucceeded {
		return fmt.Errorf("incremental run status %s (want succeeded)", incRes.Status)
	}
	incPass := incDur <= incrementalThreshold

	// --- (a) the reference list queries ----------------------------------
	step("reference list queries: %d iterations each ...", profile.ListIterations)
	queries, err := runListQueries(ctx, svc, profile.ListIterations)
	if err != nil {
		return fmt.Errorf("list queries: %w", err)
	}
	overallP95 := combineP95(queries)
	listPass := overallP95 <= listP95Threshold

	// --- report -----------------------------------------------------------
	measurements := []measurement{
		{
			label:     "list-query p95 (NFR-003, §10.4 filter read)",
			value:     durString(overallP95),
			threshold: "≤ " + durString(listP95Threshold),
			pass:      listPass,
		},
		{
			label:     "incremental run duration (NFR-004)",
			value:     durString(incDur),
			threshold: "≤ " + durString(incrementalThreshold),
			pass:      incPass,
		},
		{
			label:     "bulk-import job count (§17.1)",
			value:     fmt.Sprintf("%d job(s) total, %d matching.rebuild", totalJobs, rebuildJobs),
			threshold: fmt.Sprintf("≪ %d CVEs (jobs×%d ≤ CVEs)", profile.CVEs, jobRatioFactor),
			pass:      jobPass,
		},
	}

	report := renderReport(reportConfig{
		Version:        version,
		Profile:        profile,
		GeneratedAt:    time.Now().UTC(),
		BulkDur:        bulkDur,
		IncrementalDur: incDur,
		Outbox:         outbox,
		RebuildJobs:    rebuildJobs,
		TotalJobs:      totalJobs,
		Hits:           hits,
		Queries:        queries,
		OverallP95:     overallP95,
		Facts:          facts,
		Measurements:   measurements,
	})

	reportPath, err := writeReport(reportDir, version, profile.Name, report)
	if err != nil {
		return err
	}
	step("report written to %s", reportPath)

	// --- verdict ----------------------------------------------------------
	allPass := true
	for _, m := range measurements {
		status := "PASS"
		if !m.pass {
			status = "FAIL"
			allPass = false
		}
		fmt.Printf("  [%s] %s: %s (threshold %s)\n", status, m.label, m.value, m.threshold)
	}
	if !allPass {
		return fmt.Errorf("one or more AT-013 thresholds failed (see %s)", reportPath)
	}
	return nil
}

// ---------------------------------------------------------------------------
// database setup

// setupDatabase drops and recreates the scratch database on the admin
// server, migrates it with the full embedded migration set and returns its
// connection URL plus a cleanup that drops it again (unless keep).
func setupDatabase(ctx context.Context, adminURL string, keep bool) (string, func(), error) {
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		return "", nil, fmt.Errorf("open admin database: %w", err)
	}
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		return "", nil, fmt.Errorf("admin database not reachable (%s): %w", adminURL, err)
	}
	drop := func() {
		_, _ = admin.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+scratchDB+`" WITH (FORCE)`)
	}
	if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+scratchDB+`" WITH (FORCE)`); err != nil {
		_ = admin.Close()
		return "", nil, fmt.Errorf("drop stale scratch database: %w", err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+scratchDB+`"`); err != nil {
		_ = admin.Close()
		return "", nil, fmt.Errorf("create scratch database: %w", err)
	}

	scratchURL, err := replaceDBName(adminURL, scratchDB)
	if err != nil {
		drop()
		_ = admin.Close()
		return "", nil, err
	}

	runner, err := migrate.Open(ctx, scratchURL, migrations.FS)
	if err != nil {
		drop()
		_ = admin.Close()
		return "", nil, fmt.Errorf("open migration runner: %w", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		_ = runner.Close()
		drop()
		_ = admin.Close()
		return "", nil, fmt.Errorf("migrate scratch database: %w", err)
	}
	if err := runner.Close(); err != nil {
		drop()
		_ = admin.Close()
		return "", nil, fmt.Errorf("close migration runner: %w", err)
	}

	cleanup := func() {
		if keep {
			step("keeping scratch database %q (PERF_KEEP_DB=1)", scratchDB)
			_ = admin.Close()
			return
		}
		drop()
		_ = admin.Close()
	}
	return scratchURL, cleanup, nil
}

// replaceDBName swaps the database name of a PostgreSQL URL.
func replaceDBName(rawURL, name string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse database url: %w", err)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// newService wires the application service exactly like the production
// composition roots (all real postgres repositories, postgres.WithTx as the
// transaction boundary, an injected clock), mirroring cmd/risksignal's
// newSourceRunService.
func newService(pool *pgxpool.Pool) (*application.Service, error) {
	q := gen.New(pool)
	epssHistory, err := application.NewEpssHistoryLoader(
		repo.NewRuleRepo(q), repo.NewComponentRepo(q), repo.NewVulnerabilityMatchRepo(q), repo.NewEpssHistoryRepo(q))
	if err != nil {
		return nil, fmt.Errorf("configure epss history loader: %w", err)
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
		Clock:           clock.NewFakeClock(perfClockStart),
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	}), nil
}

// ---------------------------------------------------------------------------
// seeding

// seedInventory writes the A assets (one component each) in one transaction.
// The identity of row i is a pure function of i (deterministic, §17.2).
func seedInventory(ctx context.Context, pool *pgxpool.Pool, assets int, now time.Time) error {
	return postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		q := gen.New(pool).WithTx(tx)
		at := pgtype.Timestamptz{Time: now, Valid: true}
		for i := 1; i <= assets; i++ {
			assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
				ExternalID:  assetExternalID(i),
				Source:      "perf",
				Type:        string(domain.AssetTypeServerVM),
				Name:        fmt.Sprintf("Perf Asset %05d", i),
				Environment: string(domain.EnvironmentProduction),
				Criticality: criticalityFor(i),
				Exposure:    string(domain.ExposureInternet),
			})
			if err != nil {
				return fmt.Errorf("upsert asset %d: %w", i, err)
			}
			vn, pn, key := componentKey("v", componentProduct(i), "1.0")
			if _, err := q.InsertComponent(ctx, gen.InsertComponentParams{
				AssetID:       assetID,
				Vendor:        "v",
				Product:       componentProduct(i),
				Version:       "1.0",
				VendorNorm:    vn,
				ProductNorm:   pn,
				VersionScheme: string(domain.VersionSchemeUnknown),
				NaturalKey:    key,
				UpdatedAt:     at,
			}); err != nil {
				return fmt.Errorf("insert component %d: %w", i, err)
			}
		}
		return nil
	})
}

// seedHitSet writes the deterministic expected hit set (§17.2): for every
// relevant generated CVE (h a multiple of CVERelevance) one method-led
// match against its round-robin component and one signal. This is the same
// row set a matching.rebuild plus one signal per match would produce; the
// harness seeds it directly because it measures the read path and the
// import job count, not the matching engine (§17.1: list queries and the
// import are the measured objects).
func seedHitSet(ctx context.Context, pool *pgxpool.Pool, p Profile, now time.Time) (int, error) {
	vulnByCVE, err := vulnerabilityIDs(ctx, pool)
	if err != nil {
		return 0, err
	}
	compByIndex, err := componentIDs(ctx, pool, p.Assets)
	if err != nil {
		return 0, err
	}

	priorities := []string{
		string(domain.PriorityP1), string(domain.PriorityP2),
		string(domain.PriorityP3), string(domain.PriorityP4),
	}
	reasons := []byte("[]")
	factors := []byte("[]")

	hits := 0
	for h := p.CVERelevance; h <= p.CVEs; h += p.CVERelevance {
		hits++
		compIndex := ((h/p.CVERelevance)-1)%p.Assets + 1
		cve := cveID(h)
		vulnID, ok := vulnByCVE[cve]
		if !ok {
			return 0, fmt.Errorf("hit set: vulnerability row for %s not found (import incomplete?)", cve)
		}
		compID, ok := compByIndex[compIndex]
		if !ok {
			return 0, fmt.Errorf("hit set: component row for index %d not found", compIndex)
		}
		createdAt := now.Add(time.Duration(h) * time.Second)
		priority := priorities[(h/p.CVERelevance-1)%len(priorities)]

		if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
			q := gen.New(pool).WithTx(tx)
			matchID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
				VulnerabilityID: vulnID,
				ComponentID:     compID,
				Method:          string(domain.MatchMethodCanonicalProductRange),
				Score:           80,
				Confidence:      string(domain.ConfidenceHigh),
				RuleVersion:     domain.MatchRuleVersion,
				CreatedAt:       pgtype.Timestamptz{Time: createdAt, Valid: true},
				Reasons:         reasons,
			})
			if err != nil {
				return fmt.Errorf("insert match for %s: %w", cve, err)
			}
			if _, err := q.InsertRiskSignal(ctx, gen.InsertRiskSignalParams{
				MatchID:     matchID,
				Priority:    priority,
				Owner:       pgtype.Text{},
				DueAt:       pgtype.Timestamptz{},
				ClosedAt:    pgtype.Timestamptz{},
				RuleVersion: domain.PriorityRuleVersionI1b,
				Factors:     factors,
				CreatedAt:   pgtype.Timestamptz{Time: createdAt, Valid: true},
			}); err != nil {
				return fmt.Errorf("insert signal for %s: %w", cve, err)
			}
			return nil
		}); err != nil {
			return 0, err
		}
	}
	return hits, nil
}

// vulnerabilityIDs maps cve_id → row id for every vulnerability that
// carries a cpe_config (the relevant set).
func vulnerabilityIDs(ctx context.Context, pool *pgxpool.Pool) (map[string]pgtype.UUID, error) {
	rows, err := pool.Query(ctx, `SELECT id, cve_id FROM vulnerabilities WHERE cpe_config IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("read vulnerability ids: %w", err)
	}
	defer rows.Close()
	out := make(map[string]pgtype.UUID)
	for rows.Next() {
		var id pgtype.UUID
		var cve string
		if err := rows.Scan(&id, &cve); err != nil {
			return nil, err
		}
		out[cve] = id
	}
	return out, rows.Err()
}

// componentIDs maps the generated component index → row id (the product
// name p%05d encodes the index).
func componentIDs(ctx context.Context, pool *pgxpool.Pool, assets int) (map[int]pgtype.UUID, error) {
	rows, err := pool.Query(ctx, `SELECT id, product FROM components`)
	if err != nil {
		return nil, fmt.Errorf("read component ids: %w", err)
	}
	defer rows.Close()
	out := make(map[int]pgtype.UUID, assets)
	for rows.Next() {
		var id pgtype.UUID
		var product string
		if err := rows.Scan(&id, &product); err != nil {
			return nil, err
		}
		idx, err := strconv.Atoi(strings.TrimPrefix(product, "p"))
		if err != nil {
			continue
		}
		out[idx] = id
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// reference list queries (§10.4 filter read)

// queryStat is the measured latency distribution of one reference query.
type queryStat struct {
	name    string
	samples []time.Duration
	p95     time.Duration
}

// runListQueries runs every reference list query (the §10.4 filter read on
// the working list, at the reference volume) ListIterations times and
// returns the per-query latency distributions.
func runListQueries(ctx context.Context, svc *application.Service, iterations int) ([]queryStat, error) {
	actor := application.Actor{Type: application.ActorTypeSystem, ID: "perf"}

	p1 := domain.PriorityP1
	p2 := domain.PriorityP2
	st := domain.SignalStatusNew

	defs := []struct {
		name string
		in   application.ListSignalsInput
	}{
		{"signals (no filter, limit 100)", application.ListSignalsInput{Limit: 100, Actor: actor}},
		{"signals priority=P1", application.ListSignalsInput{Limit: 100, Priority: &p1, Actor: actor}},
		{"signals priority=P2", application.ListSignalsInput{Limit: 100, Priority: &p2, Actor: actor}},
		{"signals status=new", application.ListSignalsInput{Limit: 100, Status: &st, Actor: actor}},
		{"signals priority=P1 status=new", application.ListSignalsInput{Limit: 100, Priority: &p1, Status: &st, Actor: actor}},
	}

	stats := make([]queryStat, 0, len(defs))
	for _, d := range defs {
		samples := make([]time.Duration, 0, iterations)
		for i := 0; i < iterations; i++ {
			start := time.Now()
			if _, err := svc.ListSignals(ctx, d.in); err != nil {
				return nil, fmt.Errorf("%s: %w", d.name, err)
			}
			samples = append(samples, time.Since(start))
		}
		sorted := append([]time.Duration(nil), samples...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		stats = append(stats, queryStat{name: d.name, samples: samples, p95: percentile(sorted, 0.95)})
	}
	return stats, nil
}

// combineP95 is the p95 over every sample of every query — the NFR-003
// "95 % of the reference queries" figure.
func combineP95(stats []queryStat) time.Duration {
	var all []time.Duration
	for _, s := range stats {
		all = append(all, s.samples...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return percentile(all, 0.95)
}

// percentile returns the p-th percentile (0<p<1) of an ascending slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---------------------------------------------------------------------------
// database facts

// datasetFacts is the measured census of the reference dataset.
type datasetFacts struct {
	Vulnerabilities int
	Assets          int
	Components      int
	Matches         int
	Signals         int
}

func readDatasetFacts(ctx context.Context, pool *pgxpool.Pool) (datasetFacts, error) {
	var f datasetFacts
	for _, c := range []struct {
		table string
		dst   *int
	}{
		{"vulnerabilities", &f.Vulnerabilities},
		{"assets", &f.Assets},
		{"components", &f.Components},
		{"matches", &f.Matches},
		{"risk_signals", &f.Signals},
	} {
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+c.table).Scan(c.dst); err != nil {
			return datasetFacts{}, fmt.Errorf("count %s: %w", c.table, err)
		}
	}
	return f, nil
}

// outboxCounts returns the outbox row count per type.
func outboxCounts(ctx context.Context, pool *pgxpool.Pool) (map[string]int, error) {
	rows, err := pool.Query(ctx, `SELECT type, count(*) FROM outbox GROUP BY type ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("count outbox jobs: %w", err)
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var typ string
		var n int
		if err := rows.Scan(&typ, &n); err != nil {
			return nil, err
		}
		out[typ] = n
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// NVD source registration

// upsertSource registers the harness NVD source whose full-import lower
// bound is the fixed perfSince instant (one chunk to the fake clock's now).
func upsertSource(ctx context.Context, q *gen.Queries, endpoint string) (string, error) {
	cfg, err := json.Marshal(map[string]any{
		"full_import_since": perfSince,
	})
	if err != nil {
		return "", err
	}
	id, err := q.UpsertSource(ctx, gen.UpsertSourceParams{
		Type:     string(application.SourceTypeNVD),
		Name:     "nvd-perf",
		Endpoint: pgtype.Text{String: endpoint, Valid: true},
		Schedule: pgtype.Text{String: "@daily", Valid: true},
		Enabled:  true,
		Config:   cfg,
	})
	if err != nil {
		return "", err
	}
	return uuidString(id), nil
}

// ---------------------------------------------------------------------------
// deterministic generation helpers

// assetExternalID is the deterministic external id of asset i (1-based).
func assetExternalID(i int) string { return fmt.Sprintf("perf-asset-%05d", i) }

// componentProduct is the deterministic product name of component i.
func componentProduct(i int) string { return fmt.Sprintf("p%05d", i) }

// cveID is the deterministic CVE id of the a-th generated record (1-based).
func cveID(a int) string { return fmt.Sprintf("CVE-2026-%07d", a) }

// criticalityFor cycles the criticality so the generated assets carry a
// realistic spread (the list read does not filter on it, but the volume is
// representative).
func criticalityFor(i int) string {
	switch i % 3 {
	case 0:
		return string(domain.CriticalityCritical)
	case 1:
		return string(domain.CriticalityHigh)
	default:
		return string(domain.CriticalityNormal)
	}
}

// componentKey derives the normalised keys and the natural key of one
// generated component — the same derivation the demo seed and the inventory
// import use (domain.ComponentNaturalKey).
func componentKey(vendor, product, version string) (vendorNorm, productNorm, naturalKey string) {
	vn := strings.ToLower(strings.TrimSpace(vendor))
	pn := strings.ToLower(strings.TrimSpace(product))
	key, err := domain.ComponentNaturalKey(domain.ComponentIdentifiers{
		Vendor: vendor, Product: product, Version: version,
	}, vn, pn, "")
	if err != nil {
		panic("perf: derive component natural key: " + err.Error())
	}
	return vn, pn, key
}

// fakeNVD is the in-process, network-free NVD API 2.0 server (§17.2: no
// live dependency). It serves a generated set of records in pages of 2000
// and terminates on the empty page, exactly like the real API's window
// walk. The served set is mutated once (between the bulk import and the
// incremental run) to model a changed day.
type fakeNVD struct {
	mu             sync.Mutex
	idBase         int // CVE index of the first served record (1-based)
	count          int // served record count
	relevanceEvery int // every relevanceEvery-th served record carries a cpe_config
	assets         int // component count for the round-robin hit mapping
}

func (f *fakeNVD) set(idBase, count, relevanceEvery, assets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idBase, f.count, f.relevanceEvery, f.assets = idBase, count, relevanceEvery, assets
}

// serve renders one windowed page (startIndex pagination, resultsPerPage
// 2000, empty page past the set).
func (f *fakeNVD) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	idBase, count, rel, assets := f.idBase, f.count, f.relevanceEvery, f.assets
	f.mu.Unlock()

	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	w.Header().Set("Content-Type", "application/json")
	const perPage = 2000
	if start >= count {
		fmt.Fprintf(w, `{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"vulnerabilities":[]}`, perPage, start, count)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"vulnerabilities":[`, perPage, start, count)
	first := true
	for j := 0; j < perPage && start+j < count; j++ {
		h := start + j + 1 // 1-based within the served set
		absolute := idBase + h
		if !first {
			b.WriteByte(',')
		}
		first = false
		if rel > 0 && h%rel == 0 && assets > 0 {
			comp := ((h/rel)-1)%assets + 1
			fmt.Fprintf(&b, `{"cve":{"id":%q,"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:v:%s:1.0:*:*:*:*:*:*:*"}]}]}]}}`,
				cveID(absolute), componentProduct(comp))
			continue
		}
		fmt.Fprintf(&b, `{"cve":{"id":%q}}`, cveID(absolute))
	}
	b.WriteString(`]}`)
	_, _ = io.WriteString(w, b.String())
}

// ---------------------------------------------------------------------------
// small helpers

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func step(format string, args ...any) {
	fmt.Printf("== "+format+"\n", args...)
}

func durString(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
