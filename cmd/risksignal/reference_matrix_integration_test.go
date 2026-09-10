package main

// Integration test of the WP-3.11 reference-matrix exit criterion (DEV-054,
// ARCH-003 §8a): the all-asset-types × all-match-methods matrix against a
// real, short-lived PostgreSQL. cmd/risksignal is the composition root that
// wires the embedded migration set (db/migrations) together with the
// postgres adapter, so the fixtures are seeded through the real repositories
// exactly as production writes them (the WP-3.03 I3 component columns, the
// WP-3.03 alias_rules, the I2 vulnerabilities) and the engine reads its
// components back through the inventory product index (ADR-012).
//
// The versioned fixtures (testdata/reference-matrix) are the reference
// matrix: inventory.csv carries one asset of every AssetType with one
// component per identifier shape (CPE/purl/image+digest/vendor-product) and
// vulnerabilities.json carries one cell per MatchMethod (including the
// candidate similarity band and no_match) with the ADR-015 expected
// method/confidence/score and a TR-007 reason token. They are seeded
// directly via repo/SQL, never through the CSV import pipeline (DEV-048 is
// not a dependency; the fixtures are pure test data).
//
// Three proofs:
//
//   (a) the pure matcher, fed the DB-seeded components (read back through the
//       repository) and the DB-seeded alias rules, yields the exact cell of
//       every (asset_type, method) pair — method/confidence/score and a
//       non-empty reason list carrying the cell's token;
//   (b) the matching core (RunMatching) persists every cell as a real match
//       row, and a second run with the same composite rule version writes
//       nothing new — UQ (vulnerability_id, component_id, rule_version) makes
//       the insert idempotent;
//   (c) the index/pre-filter and the inventory-driven rebuild: the candidate
//       pre-filter (CandidateComponentIDs over the product index) resolves
//       exactly the components meeting a name pair and none for a pair with
//       no inventory, and running matching.rebuild twice over the same
//       (rule_version, inventory_snapshot) leaves one match row per pair.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/matching"
	"github.com/brunoxpera/risksignal/internal/application/normalise"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// refMatrixDigest is the synthetic immutable digest of the container fixture
// (64 hex digits after the algorithm).
const refMatrixDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// refMatrixAt is the fixed instant the fixture rows are stamped with (the
// injected clock), so every updated_at is deterministic.
var refMatrixAt = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)

// refMatrixFixtureFile / refMatrixInventoryFile are the versioned fixtures.
const (
	refMatrixFixtureFile   = "testdata/reference-matrix/vulnerabilities.json"
	refMatrixInventoryFile = "testdata/reference-matrix/inventory.csv"
	refMatrixNoRulesKeys   = "a0000000001d0000000000" // alias v1 + decision v0 (the fixture has two alias rules)
	refMatrixEmptyRulesKey = "a0000000000d0000000000" // no rules configured (the pre-filter test)
)

// refMatrixStatement / refMatrixRange / refMatrixCell / refMatrixAliasRule /
// refMatrixFixture are the JSON shape of vulnerabilities.json.
type refMatrixStatement struct {
	Vendor        string           `json:"vendor"`
	Product       string           `json:"product"`
	CPE           string           `json:"cpe"`
	PURL          string           `json:"purl"`
	Repository    string           `json:"repository"`
	Digest        string           `json:"digest"`
	ExactVersions []string         `json:"exact_versions"`
	Ranges        []refMatrixRange `json:"ranges"`
}

type refMatrixRange struct {
	Start          string `json:"start"`
	StartIncluding bool   `json:"start_including"`
	End            string `json:"end"`
	EndIncluding   bool   `json:"end_including"`
}

type refMatrixCell struct {
	ComponentFX    string               `json:"component_fx"`
	CVEID          string               `json:"cve_id"`
	Method         string               `json:"method"`
	Confidence     string               `json:"confidence"`
	Score          int                  `json:"score"`
	ReasonContains string               `json:"reason_contains"`
	Statements     []refMatrixStatement `json:"statements"`
}

type refMatrixAliasRule struct {
	Scope   string `json:"scope"`
	From    string `json:"from"`
	To      string `json:"to"`
	Version int32  `json:"version"`
	Reason  string `json:"reason"`
}

type refMatrixFixture struct {
	AliasRules []refMatrixAliasRule `json:"alias_rules"`
	Cells      []refMatrixCell      `json:"cells"`
}

// refMatrixInventoryRow is one parsed inventory.csv row (the canonical 15
// ARCH-003 §1.3 columns plus the fixture-only fx_key correlation column).
type refMatrixInventoryRow struct {
	Source, ExternalID, Type, Name, Environment, Criticality, Exposure, Owner string
	Vendor, Product, Version, CPE, PURL, Image, Digest, FX                    string
}

// loadRefMatrixFixture reads and decodes vulnerabilities.json.
func loadRefMatrixFixture(t *testing.T) refMatrixFixture {
	t.Helper()
	b, err := os.ReadFile(refMatrixFixtureFile)
	if err != nil {
		t.Fatalf("read %s: %v", refMatrixFixtureFile, err)
	}
	var f refMatrixFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("decode %s: %v", refMatrixFixtureFile, err)
	}
	if len(f.Cells) == 0 || len(f.AliasRules) == 0 {
		t.Fatalf("fixture %s is empty (cells %d, alias rules %d)", refMatrixFixtureFile, len(f.Cells), len(f.AliasRules))
	}
	return f
}

// loadRefMatrixInventory reads inventory.csv (header-mapped, so the column
// order stays free), returning the rows in file order.
func loadRefMatrixInventory(t *testing.T) []refMatrixInventoryRow {
	t.Helper()
	f, err := os.Open(refMatrixInventoryFile)
	if err != nil {
		t.Fatalf("open %s: %v", refMatrixInventoryFile, err)
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse %s: %v", refMatrixInventoryFile, err)
	}
	if len(records) < 2 {
		t.Fatalf("inventory fixture %s has no data rows", refMatrixInventoryFile)
	}
	col := make(map[string]int, len(records[0]))
	for i, name := range records[0] {
		col[name] = i
	}
	get := func(rec []string, name string) string { return rec[col[name]] }
	rows := make([]refMatrixInventoryRow, 0, len(records)-1)
	for _, rec := range records[1:] {
		rows = append(rows, refMatrixInventoryRow{
			Source: get(rec, "source"), ExternalID: get(rec, "external_id"), Type: get(rec, "type"),
			Name: get(rec, "name"), Environment: get(rec, "environment"), Criticality: get(rec, "criticality"),
			Exposure: get(rec, "exposure"), Owner: get(rec, "owner"),
			Vendor: get(rec, "vendor"), Product: get(rec, "product"), Version: get(rec, "version"),
			CPE: get(rec, "cpe"), PURL: get(rec, "purl"), Image: get(rec, "image"), Digest: get(rec, "digest"),
			FX: get(rec, "fx_key"),
		})
	}
	return rows
}

// refMatrixComponentColumns derives the WP-3.03 write-time columns of one
// fixture row exactly as the import layer does (inventory_import.go): the
// normalised comparison keys (normalise.NormaliseKey), the inferred version
// scheme (normalise.InferVersionScheme) and the derived natural key
// (domain.ComponentNaturalKey); version_norm stays empty (no version
// normaliser exists yet).
func refMatrixComponentColumns(t *testing.T, row refMatrixInventoryRow) (ids domain.ComponentIdentifiers, vendorNorm, productNorm, scheme, naturalKey string) {
	t.Helper()
	ids = domain.ComponentIdentifiers{
		Vendor: row.Vendor, Product: row.Product, Version: row.Version,
		CPE: row.CPE, PURL: row.PURL, Image: row.Image, Digest: row.Digest,
	}
	vendorNorm = normalise.NormaliseKey(row.Vendor)
	productNorm = normalise.NormaliseKey(row.Product)
	scheme = string(normalise.InferVersionScheme(ids, domain.VersionSchemeUnknown))
	key, err := domain.ComponentNaturalKey(ids, vendorNorm, productNorm, "")
	if err != nil {
		t.Fatalf("ComponentNaturalKey(%+v): %v", ids, err)
	}
	return ids, vendorNorm, productNorm, scheme, key
}

// refMatrixSeed is the seeded fixture state: the component id and full read
// model of every (asset external_id, fx_key) fixture component, plus the
// vulnerability row ids by cell cve_id and the alias rules.
type refMatrixSeed struct {
	componentIDs map[string]map[string]string // external_id -> fx_key -> component row id
	components   map[string]application.Component
	vulnIDs      map[string]string // cve_id -> vulnerability row id
	vulnUUIDs    map[string]pgtype.UUID
	aliasRules   []domain.AliasRule
	assetIDs     map[string]pgtype.UUID
}

// seedRefMatrixFixture seeds the whole reference matrix through the real
// postgres repositories: one asset per AssetType, one component per its
// identifier shapes (the WP-3.03 column set), the two controlled alias rules
// and the nine cell vulnerabilities.
func seedRefMatrixFixture(t *testing.T, ctx context.Context, q *gen.Queries, fx refMatrixFixture, rows []refMatrixInventoryRow) refMatrixSeed {
	t.Helper()
	seed := refMatrixSeed{
		componentIDs: make(map[string]map[string]string),
		components:   make(map[string]application.Component),
		vulnIDs:      make(map[string]string),
		vulnUUIDs:    make(map[string]pgtype.UUID),
		assetIDs:     make(map[string]pgtype.UUID),
	}
	at := pgtype.Timestamptz{Time: refMatrixAt, Valid: true}

	// Assets + components.
	for _, row := range rows {
		assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
			ExternalID: row.ExternalID, Source: row.Source, Type: row.Type, Name: row.Name,
			Environment: row.Environment, Criticality: row.Criticality, Exposure: row.Exposure,
		})
		if err != nil {
			t.Fatalf("UpsertAsset(%s): %v", row.ExternalID, err)
		}
		seed.assetIDs[row.ExternalID] = assetID
		ids, vendorNorm, productNorm, scheme, naturalKey := refMatrixComponentColumns(t, row)
		componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
			AssetID:       assetID,
			Vendor:        ids.Vendor,
			Product:       ids.Product,
			Version:       ids.Version,
			Cpe:           refMatrixTextOpt(ids.CPE),
			Purl:          refMatrixTextOpt(ids.PURL),
			Image:         refMatrixTextOpt(ids.Image),
			Digest:        refMatrixTextOpt(ids.Digest),
			VendorNorm:    vendorNorm,
			ProductNorm:   productNorm,
			VersionNorm:   pgtype.Text{},
			VersionScheme: scheme,
			NaturalKey:    naturalKey,
			UpdatedAt:     at,
		})
		if err != nil {
			t.Fatalf("InsertComponent(%s/%s): %v", row.ExternalID, row.FX, err)
		}
		if seed.componentIDs[row.ExternalID] == nil {
			seed.componentIDs[row.ExternalID] = make(map[string]string)
		}
		seed.componentIDs[row.ExternalID][row.FX] = demoUUID(componentID)

		// Read the full I3 row back through the repository (the same read the
		// matcher's candidate assembly uses) and build the domain engine
		// input from it — so the matrix evaluates the stored rows, not the
		// fixture structs.
		full, err := repo.NewComponentRepo(q).ListComponentsByIDs(ctx, []string{demoUUID(componentID)})
		if err != nil || len(full) != 1 {
			t.Fatalf("ListComponentsByIDs(%s): %v (%d rows)", demoUUID(componentID), err, len(full))
		}
		seed.components[demoUUID(componentID)] = full[0]
	}

	// Alias rules (the controlled aliases the two alias cells need).
	for i, ar := range fx.AliasRules {
		scope, err := domain.ParseAliasScope(ar.Scope)
		if err != nil {
			t.Fatalf("alias rule %d scope: %v", i, err)
		}
		rule, err := domain.NewAliasRule("ref-alias-"+ar.Scope+"-"+ar.From, scope, ar.From, ar.To, ar.Reason, int(ar.Version))
		if err != nil {
			t.Fatalf("alias rule %d: %v", i, err)
		}
		seed.aliasRules = append(seed.aliasRules, rule)
		if _, err := q.InsertAliasRule(ctx, gen.InsertAliasRuleParams{
			Scope: ar.Scope, FromValue: ar.From, ToValue: ar.To, Version: ar.Version,
			Enabled: true, Reason: pgtype.Text{String: ar.Reason, Valid: true},
			CreatedAt: at, UpdatedAt: at,
		}); err != nil {
			t.Fatalf("InsertAliasRule(%s %s->%s): %v", ar.Scope, ar.From, ar.To, err)
		}
	}

	// Cell vulnerabilities (the statements travel directly into the engine;
	// the matrix does not depend on the cpe_config decomposition — that path
	// is exercised by the index/pre-filter test below and by the WP-3.09
	// wiring tests).
	for _, cell := range fx.Cells {
		vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
			CveID:       cell.CVEID,
			Summary:     "reference-matrix cell " + cell.Method,
			PublishedAt: at,
			ModifiedAt:  at,
		})
		if err != nil {
			t.Fatalf("UpsertVulnerability(%s): %v", cell.CVEID, err)
		}
		seed.vulnIDs[cell.CVEID] = demoUUID(vulnID)
		seed.vulnUUIDs[cell.CVEID] = vulnID
	}
	return seed
}

// refMatrixTextOpt maps "" to a NULL text column (the same convention as the
// repository's toTextOpt).
func refMatrixTextOpt(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// refMatrixStatements converts the fixture statements to the engine input.
func refMatrixStatements(stmts []refMatrixStatement) []matching.AffectedProduct {
	out := make([]matching.AffectedProduct, 0, len(stmts))
	for _, s := range stmts {
		ap := matching.AffectedProduct{
			Vendor: s.Vendor, Product: s.Product, CPE: s.CPE, PURL: s.PURL,
			Repository: s.Repository, Digest: s.Digest, ExactVersions: s.ExactVersions,
		}
		for _, r := range s.Ranges {
			ap.Ranges = append(ap.Ranges, domain.VersionRange{
				Start: r.Start, StartIncluding: r.StartIncluding, End: r.End, EndIncluding: r.EndIncluding,
			})
		}
		out = append(out, ap)
	}
	return out
}

// TestReferenceMatrixAllAssetTypesAndMethods is the reference-matrix exit
// criterion (ARCH-003 §8a) at the integration level: every (AssetType,
// MatchMethod) cell is evaluated against the DB-seeded fixture component and
// asserted for the exact method/confidence/score and a TR-007 reason token;
// the matching core then persists every cell as a real match row and a second
// run (same composite rule version) adds nothing — UQ (vulnerability_id,
// component_id, rule_version) is idempotent.
func TestReferenceMatrixAllAssetTypesAndMethods(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	q := gen.New(pool)
	clk := clock.NewFakeClock(refMatrixAt)

	fx := loadRefMatrixFixture(t)
	rows := loadRefMatrixInventory(t)
	seed := seedRefMatrixFixture(t, ctx, q, fx, rows)

	// Validate the fixture shape: every cell maps to a fixture component and
	// the alias version matches the composite rule version we assert under.
	if got, want := len(fx.Cells), 9; got != want {
		t.Fatalf("fixture cells = %d, want %d (one per MatchMethod, candidate and no_match included)", got, want)
	}
	fxCov := make(map[string]bool)
	for _, r := range rows {
		fxCov[r.FX] = true
	}
	for _, cell := range fx.Cells {
		if !fxCov[cell.ComponentFX] {
			t.Fatalf("cell %s references component_fx %q not present in the inventory fixture", cell.CVEID, cell.ComponentFX)
		}
	}

	svc := newCreateSignalService(pool, repo.NewOutboxRepo(q), clk)

	assetOrder := refMatrixAssetOrder(rows)
	cells := 0
	var batch []application.MatchCandidate
	for _, cell := range fx.Cells {
		for _, ext := range assetOrder {
			cells++
			compID := seed.componentIDs[ext][cell.ComponentFX]
			comp := seed.components[compID]
			if cell.ComponentFX == "digest" && comp.Digest != refMatrixDigest {
				t.Fatalf("digest fixture component carries %q, want %q", comp.Digest, refMatrixDigest)
			}
			dc, err := domain.NewComponent(comp.ID, comp.AssetID, domain.ComponentIdentifiers{
				Vendor: comp.Vendor, Product: comp.Product, Version: comp.Version,
				CPE: comp.CPE, PURL: comp.PURL, Image: comp.Image, Digest: comp.Digest,
			}, comp.VendorNorm, comp.ProductNorm, comp.VersionNorm, comp.VersionScheme)
			if err != nil {
				t.Fatalf("domain.NewComponent(%s/%s): %v", ext, cell.ComponentFX, err)
			}
			in := matching.Input{
				CVEID:           cell.CVEID,
				Statements:      refMatrixStatements(cell.Statements),
				Component:       dc,
				AliasRules:      seed.aliasRules,
				AliasVersion:    1,
				DecisionVersion: 0,
				Now:             refMatrixAt,
			}
			out, err := matching.Evaluate(in)
			if err != nil {
				t.Fatalf("%s/%s/%s: Evaluate: %v", ext, cell.ComponentFX, cell.Method, err)
			}
			if string(out.Method) != cell.Method || string(out.Confidence) != cell.Confidence || out.Score != cell.Score {
				t.Fatalf("cell (%s, %s) = %s/%s/%d, want %s/%s/%d",
					ext, cell.Method, out.Method, out.Confidence, out.Score,
					cell.Method, cell.Confidence, cell.Score)
			}
			if len(out.Reasons) == 0 {
				t.Fatalf("cell (%s, %s): empty TR-007 reason list", ext, cell.Method)
			}
			if !refMatrixAnyReasonContains(out.Reasons, cell.ReasonContains) {
				t.Fatalf("cell (%s, %s): reasons %v do not carry %q", ext, cell.Method, out.Reasons, cell.ReasonContains)
			}
			if out.RuleVersion != refMatrixNoRulesKeys {
				t.Fatalf("cell (%s, %s): rule_version %q, want %q", ext, cell.Method, out.RuleVersion, refMatrixNoRulesKeys)
			}
			batch = append(batch, application.MatchCandidate{VulnerabilityID: seed.vulnIDs[cell.CVEID], Evaluation: in})
		}
	}

	// (b) persist every cell and assert the stored triple round-trips.
	run, err := svc.RunMatching(ctx, batch)
	if err != nil {
		t.Fatalf("RunMatching: %v", err)
	}
	if run.Candidates != cells {
		t.Fatalf("RunMatching candidates = %d, want %d", run.Candidates, cells)
	}
	if n := countTableRows(t, pool, "matches"); n != cells {
		t.Fatalf("match rows after the first run = %d, want %d (one per cell)", n, cells)
	}
	for _, cell := range fx.Cells {
		for _, ext := range assetOrder {
			compID := seed.componentIDs[ext][cell.ComponentFX]
			var method, confidence string
			var score int
			var reasons []byte
			if err := pool.QueryRow(ctx,
				`SELECT method, confidence, score, reasons FROM matches
				 WHERE vulnerability_id = $1 AND component_id = $2 AND rule_version = $3`,
				seed.vulnUUIDs[cell.CVEID], mustUUID(t, compID), refMatrixNoRulesKeys).
				Scan(&method, &confidence, &score, &reasons); err != nil {
				t.Fatalf("read stored match (%s, %s): %v", ext, cell.Method, err)
			}
			if method != cell.Method || confidence != cell.Confidence || score != cell.Score {
				t.Fatalf("stored match (%s, %s) = %s/%s/%d, want %s/%s/%d",
					ext, cell.Method, method, confidence, score, cell.Method, cell.Confidence, cell.Score)
			}
			var list []string
			if err := json.Unmarshal(reasons, &list); err != nil || len(list) == 0 {
				t.Fatalf("stored match (%s, %s): reasons %s (decode err %v), want a non-empty list", ext, cell.Method, reasons, err)
			}
		}
	}

	// A second run under the same rule version adds nothing (idempotent).
	if _, err := svc.RunMatching(ctx, batch); err != nil {
		t.Fatalf("RunMatching (second run): %v", err)
	}
	if n := countTableRows(t, pool, "matches"); n != cells {
		t.Fatalf("match rows after the second run = %d, want still %d (UQ is idempotent)", n, cells)
	}
}

// TestReferenceMatrixPrefilterAndRebuildIdempotency proves the index/
// pre-filter seam and the inventory-driven rebuild (ARCH-003 §4/§5): the
// candidate pre-filter resolves exactly the components meeting a CVE name
// pair through the product index and none for an unrelated pair, and running
// matching.rebuild twice over the same (rule_version, inventory_snapshot)
// leaves one match row per pair — the UQ (vulnerability_id, component_id,
// rule_version) idempotency through the real rebuild path.
func TestReferenceMatrixPrefilterAndRebuildIdempotency(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	q := gen.New(pool)
	clk := clock.NewFakeClock(refMatrixAt)
	at := pgtype.Timestamptz{Time: refMatrixAt, Valid: true}

	// One asset with the Acme Widget 1.2.3 component.
	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID: "a1", Source: "cmdb", Type: "server_vm", Name: "Portal",
		Environment: "production", Criticality: "high", Exposure: "internet",
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	vendorNorm, productNorm, naturalKey, err := seededComponentKey("Acme", "Widget", "1.2.3")
	if err != nil {
		t.Fatalf("seededComponentKey: %v", err)
	}
	componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID: assetID, Vendor: "Acme", Product: "Widget", Version: "1.2.3",
		VendorNorm: vendorNorm, ProductNorm: productNorm, VersionScheme: string(domain.VersionSchemeUnknown),
		NaturalKey: naturalKey, UpdatedAt: at,
	})
	if err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}

	// V1 names the affected acme/widget pair; V2 names a product with no
	// inventory (the pre-filter gate: no candidate ⇒ no work).
	v1, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: "CVE-2026-2001", Summary: "widget rce", PublishedAt: at, ModifiedAt: at,
		CpeConfig: []byte(`[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"}]}]}]`),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability V1: %v", err)
	}
	v2, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID: "CVE-2026-2002", Summary: "unrelated", PublishedAt: at, ModifiedAt: at,
		CpeConfig: []byte(`[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:zzz:nothing:1.0:*:*:*:*:*:*:*"}]}]}]`),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability V2: %v", err)
	}

	// (index/pre-filter) The product index resolves the component for the
	// affected pair and nothing for the unrelated pair.
	lister := repo.NewComponentRepo(q)
	got, err := application.CandidateComponentIDs(ctx, []application.VendorProductPair{{Vendor: "acme", Product: "widget"}}, nil, lister)
	if err != nil {
		t.Fatalf("CandidateComponentIDs(acme/widget): %v", err)
	}
	if len(got) != 1 || got[0] != demoUUID(componentID) {
		t.Fatalf("CandidateComponentIDs(acme/widget) = %v, want exactly the component %s", got, demoUUID(componentID))
	}
	none, err := application.CandidateComponentIDs(ctx, []application.VendorProductPair{{Vendor: "zzz", Product: "nothing"}}, nil, lister)
	if err != nil {
		t.Fatalf("CandidateComponentIDs(zzz/nothing): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("CandidateComponentIDs(zzz/nothing) = %v, want no candidates", none)
	}

	// The inventory-driven rebuild, twice.
	svc := newCreateSignalService(pool, repo.NewOutboxRepo(q), clk)
	runner, err := application.NewMatchingRunner(svc, repo.NewRuleRepo(q), repo.NewComponentRepo(q), repo.NewVulnerabilityMatchRepo(q), clk, nil)
	if err != nil {
		t.Fatalf("NewMatchingRunner: %v", err)
	}
	const snapshot = "ref-matrix-inventory-snapshot"
	for run := 1; run <= 2; run++ {
		res, err := runner.RebuildMatching(ctx, application.RebuildMatchingInput{
			RuleVersion: refMatrixEmptyRulesKey, InventorySnapshot: snapshot,
		})
		if err != nil {
			t.Fatalf("RebuildMatching (run %d): %v", run, err)
		}
		if res.Components != 1 {
			t.Fatalf("rebuild (run %d) walked %d components, want 1", run, res.Components)
		}
		// Exactly one match row for the affected pair, none for the
		// unrelated CVE, after every run.
		if n := refMatrixPairMatches(t, ctx, pool, v1, componentID); n != 1 {
			t.Fatalf("rebuild (run %d): matches for (V1, widget) = %d, want 1", run, n)
		}
		if n := refMatrixPairMatches(t, ctx, pool, v2, componentID); n != 0 {
			t.Fatalf("rebuild (run %d): matches for (V2, widget) = %d, want 0 (no candidate ⇒ no work)", run, n)
		}
	}

	// The stored row carries the canonical-product-range cell of the
	// name-meeting pair with the exactly affected version.
	var method, confidence, ruleVersion string
	var score int
	if err := pool.QueryRow(ctx,
		`SELECT method, confidence, score, rule_version FROM matches
		 WHERE vulnerability_id = $1 AND component_id = $2`,
		v1, componentID).Scan(&method, &confidence, &score, &ruleVersion); err != nil {
		t.Fatalf("read rebuild match: %v", err)
	}
	if method != string(domain.MatchMethodCanonicalProductRange) || confidence != string(domain.ConfidenceHigh) || score != 80 {
		t.Fatalf("rebuild match = %s/%s/%d, want canonical_product_range/high/80", method, confidence, score)
	}
	if ruleVersion != refMatrixEmptyRulesKey {
		t.Fatalf("rebuild match rule_version = %q, want %q", ruleVersion, refMatrixEmptyRulesKey)
	}
}

// refMatrixPairMatches counts the match rows of one (vulnerability, component)
// pair across all rule versions.
func refMatrixPairMatches(t *testing.T, ctx context.Context, pool *pgxpool.Pool, vulnID, compID pgtype.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM matches WHERE vulnerability_id = $1 AND component_id = $2",
		vulnID, compID).Scan(&n); err != nil {
		t.Fatalf("count pair matches: %v", err)
	}
	return n
}

// refMatrixAssetOrder returns the distinct asset external_ids in fixture
// order (one per AssetType).
func refMatrixAssetOrder(rows []refMatrixInventoryRow) []string {
	seen := make(map[string]bool)
	var order []string
	for _, r := range rows {
		if !seen[r.ExternalID] {
			seen[r.ExternalID] = true
			order = append(order, r.ExternalID)
		}
	}
	return order
}

// refMatrixAnyReasonContains reports whether any reason carries sub.
func refMatrixAnyReasonContains(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}
