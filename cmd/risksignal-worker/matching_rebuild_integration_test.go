package main

// End-to-end integration test of the WP-3.08/3.09 matching pipeline at
// the composition root (cmd/risksignal-worker is where the embedded
// migration set is wired together with the postgres adapter, the worker
// relay and — since DEV-065 — the matching job handlers, so the full
// chain is exercised here against a real, short-lived PostgreSQL):
//
//   - seed one vulnerability whose stored NVD configurations block
//     (vulnerabilities.cpe_config) names an affected acme/widget pair;
//   - commit an inventory CSV whose component row is Acme Widget 1.2.3:
//     CommitInventory writes the asset + component and enqueues exactly
//     one matching.rebuild job (rule_version + inventory snapshot of the
//     ARCH-003 §5 dedupe key);
//   - one relay drain consumes the job through the registered
//     matching.rebuild handler — the postgres matching read adapters
//     resolve the candidates (rules state, keyset component page, the
//     reverse pair read over the decomposed cpe_config) and the
//     application matching core writes the method-led match row;
//   - a second inventory commit (a further asset — a changed inventory
//     snapshot) enqueues a second matching.rebuild and the drain re-runs
//     it: the idempotent match insert (UQ (vulnerability_id,
//     component_id, rule_version)) keeps the pair's row count at one —
//     rebuild twice, zero duplicates (TR-012);
//   - an enqueued matching.recompute batch over the same vulnerability id
//     drains to the same single row (idempotent overlap, no dead-letter).
//
// The test also pins the matching read adapters against the real schema:
// the rule-state reads (effective alias/decision rules of the current
// ruleset + the version counters) and the not-found classification of the
// by-id reads. Like the other integration tests it skips when no
// PostgreSQL is reachable.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/adapters/worker"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// newMigratedWorkerPool creates a dedicated database for one test case,
// migrates it with the full embedded set and opens the pool under test on
// it. Tests skip when no PostgreSQL is reachable.
func newMigratedWorkerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	runner, err := migrate.Open(ctx, dbURL, migrations.FS)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if _, err := runner.Migrate(ctx, false); err != nil {
		_ = runner.Close()
		t.Fatalf("fresh migrate: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close migration runner: %v", err)
	}

	pool, err := postgres.OpenPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("postgres.OpenPool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// inventoryCSV joins the canonical ARCH-003 §1.3 inventory header with the
// given data rows (the same 15-column shape the application parser locks).
func inventoryCSV(rows ...string) string {
	const header = "source,external_id,type,name,environment,criticality,exposure,owner,vendor,product,version,cpe,purl,image,digest"
	return strings.Join(append([]string{header}, rows...), "\n") + "\n"
}

// inventoryRow renders one vendor/product/version-only inventory row of
// one asset in the canonical 15-column order.
func inventoryRow(source, external, name, vendor, product, version string) string {
	return strings.Join([]string{source, external, "server_vm", name, "production", "high", "internet", "", vendor, product, version, "", "", "", ""}, ",")
}

// matchState is the observable state of one outbox row.
func readOutboxStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id pgtype.UUID) string {
	t.Helper()
	var status string
	if err := pool.QueryRow(ctx, "SELECT status FROM outbox WHERE id = $1", id).Scan(&status); err != nil {
		t.Fatalf("read outbox row %s: %v", id, err)
	}
	return status
}

// countMatches counts the stored match rows of one (vulnerability,
// component) pair under one rule version.
func countMatches(t *testing.T, ctx context.Context, pool *pgxpool.Pool, vulnID, compID pgtype.UUID, ruleVersion string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM matches WHERE vulnerability_id = $1 AND component_id = $2 AND rule_version = $3",
		vulnID, compID, ruleVersion).Scan(&n); err != nil {
		t.Fatalf("count match rows: %v", err)
	}
	return n
}

// TestInventoryCommitRebuildDrainsToMatchesWithoutDuplicates is the
// DEV-065 acceptance test: the matching.rebuild job a real inventory
// commit enqueues is consumed by the worker (registered matching
// handlers) and produces the matches of the committed inventory; a
// second rebuild over the changed inventory leaves the pair's row count
// untouched — no duplicates.
func TestInventoryCommitRebuildDrainsToMatchesWithoutDuplicates(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	q := gen.New(pool)
	noRulesRuleVersion := "a0000000000d0000000000"

	// The production composition of runWithContext: the application
	// service (the matching core) over the postgres repos, the relay with
	// the matching job handlers registered on the matching.rebuild /
	// matching.recompute registry keys.
	svc := application.NewService(application.ServiceDeps{
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
		Clock:           clock.RealClock{},
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), discardLogger())
	if err != nil {
		t.Fatalf("worker.NewRelay: %v", err)
	}
	runner, err := application.NewMatchingRunner(svc,
		repo.NewRuleRepo(q), repo.NewComponentRepo(q), repo.NewVulnerabilityMatchRepo(q),
		clock.RealClock{}, discardLogger())
	if err != nil {
		t.Fatalf("application.NewMatchingRunner: %v", err)
	}
	matchingJobs, err := worker.NewMatchingJobs(runner, discardLogger())
	if err != nil {
		t.Fatalf("worker.NewMatchingJobs: %v", err)
	}
	if err := matchingJobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}

	// One vulnerability whose stored NVD configurations block names an
	// affected Acme Widget version window (the raw block the I2 ingest
	// stores; the read adapter decomposes it at match time).
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       "CVE-2026-0770",
		Summary:     "Widget remote code execution",
		PublishedAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC), Valid: true},
		ModifiedAt:  pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC), Valid: true},
		CpeConfig: []byte(`[
  {
    "nodes": [
      {
        "operator": "OR",
        "negate": false,
        "cpeMatch": [
          {
            "vulnerable": true,
            "criteria": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*",
            "matchCriteriaId": "ABCDEF12-3456-7890-ABCD-EF1234567890"
          }
        ]
      }
    ],
    "operator": "OR"
  }
]`),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}

	// First inventory commit: one asset with the Acme Widget 1.2.3
	// component. The commit writes the inventory and enqueues exactly one
	// matching.rebuild job under the empty ruleset composite.
	res, err := svc.CommitInventory(ctx, application.CommitInventoryInput{
		File: []byte(inventoryCSV(inventoryRow("cmdb", "a1", "Portal", "Acme", "Widget", "1.2.3"))),
	})
	if err != nil {
		t.Fatalf("first CommitInventory: %v", err)
	}
	if !res.Changed || res.AssetsCreated != 1 || res.ComponentsCreated != 1 {
		t.Fatalf("first commit report: changed=%v assets=%d components=%d", res.Changed, res.AssetsCreated, res.ComponentsCreated)
	}
	if res.RuleVersion != noRulesRuleVersion {
		t.Fatalf("first commit rule_version = %q, want %q (no rules configured)", res.RuleVersion, noRulesRuleVersion)
	}
	var pending int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE type = 'matching.rebuild' AND status = 'pending'").Scan(&pending); err != nil {
		t.Fatalf("count pending rebuild jobs: %v", err)
	}
	if pending != 1 {
		t.Fatalf("pending matching.rebuild jobs after the first commit = %d, want 1", pending)
	}

	// One drain: the rebuild job is claimed, dispatched to the registered
	// matching.rebuild handler and acked; the run walks the committed
	// component, resolves the candidate CVE through the reverse pair read
	// over the decomposed cpe_config and writes the method-led match row.
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if n := countMatches(t, ctx, pool, vulnID, componentRowID(t, ctx, q), noRulesRuleVersion); n != 1 {
		t.Fatalf("match rows after the first rebuild = %d, want 1", n)
	}

	// The stored match carries the engine outcome of the canonical name
	// pair with the exactly affected version: canonical_product_range /
	// high / 80 under the composite rule version of the empty ruleset.
	var method, confidence, ruleVersion string
	var score int32
	if err := pool.QueryRow(ctx,
		"SELECT method, confidence, score, rule_version FROM matches WHERE vulnerability_id = $1 AND rule_version = $2",
		vulnID, noRulesRuleVersion).Scan(&method, &confidence, &score, &ruleVersion); err != nil {
		t.Fatalf("read match row: %v", err)
	}
	if method != string(domain.MatchMethodCanonicalProductRange) || confidence != string(domain.ConfidenceHigh) || score != 80 {
		t.Fatalf("match = %s/%s/%d, want canonical_product_range/high/80", method, confidence, score)
	}

	// Second inventory commit — a further asset changes the inventory
	// snapshot (ARCH-003 §5: any inventory mutation bumps the hash), so a
	// fresh matching.rebuild is enqueued. The drain re-runs the rebuild
	// over both components: the Widget pair re-evaluates to the already
	// stored row (the idempotent insert keeps the count at one — rebuild
	// twice, zero duplicates) and the Portal component (no affected CVE)
	// resolves no candidates.
	second, err := svc.CommitInventory(ctx, application.CommitInventoryInput{
		File: []byte(inventoryCSV(
			inventoryRow("cmdb", "a1", "Portal", "Acme", "Widget", "1.2.3"),
			inventoryRow("cmdb", "a2", "Docs", "Acme", "Portal", "2.0.0"),
		)),
	})
	if err != nil {
		t.Fatalf("second CommitInventory: %v", err)
	}
	if !second.Changed {
		t.Fatal("second commit (additional asset) must report changed")
	}
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if n := countMatches(t, ctx, pool, vulnID, componentRowID(t, ctx, q), noRulesRuleVersion); n != 1 {
		t.Fatalf("match rows after the second rebuild = %d, want 1 (no duplicates)", n)
	}
	var deadLetters int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM outbox WHERE status = 'dead_letter'").Scan(&deadLetters); err != nil {
		t.Fatalf("count dead-lettered rows: %v", err)
	}
	if deadLetters != 0 {
		t.Fatalf("dead-lettered outbox rows = %d, want 0", deadLetters)
	}
}

// componentRowID resolves the stored component row id of the seeded Acme
// Widget 1.2.3 component through the product index read.
func componentRowID(t *testing.T, ctx context.Context, q *gen.Queries) pgtype.UUID {
	t.Helper()
	rows, err := q.ListComponentsByVendorProductNorm(ctx, gen.ListComponentsByVendorProductNormParams{
		VendorNorm:  "acme",
		ProductNorm: "widget",
	})
	if err != nil {
		t.Fatalf("ListComponentsByVendorProductNorm: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("product index rows for acme/widget = %d, want 1", len(rows))
	}
	return rows[0].ID
}

// TestMatchingRecomputeBatchDrainsIdempotentlyOverTheStoredRow pins the
// matching.recompute handler registration: an enqueued pre-filtered batch
// (the WP-3.09 incremental shape) over the vulnerability of the earlier
// rebuild drains through ListByIDs + the candidate pre-filter and lands
// on the already stored match row — the idempotent insert leaves one row
// and the job is acked, never dead-lettered.
func TestMatchingRecomputeBatchDrainsIdempotentlyOverTheStoredRow(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	q := gen.New(pool)
	ruleVersion := "a0000000000d0000000000"

	svc := application.NewService(application.ServiceDeps{
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
		Clock:           clock.RealClock{},
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), discardLogger())
	if err != nil {
		t.Fatalf("worker.NewRelay: %v", err)
	}
	runner, err := application.NewMatchingRunner(svc,
		repo.NewRuleRepo(q), repo.NewComponentRepo(q), repo.NewVulnerabilityMatchRepo(q),
		clock.RealClock{}, discardLogger())
	if err != nil {
		t.Fatalf("application.NewMatchingRunner: %v", err)
	}
	matchingJobs, err := worker.NewMatchingJobs(runner, discardLogger())
	if err != nil {
		t.Fatalf("worker.NewMatchingJobs: %v", err)
	}
	if err := matchingJobs.RegisterHandlers(relay); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}

	// The same fixture as the rebuild test: one affected vulnerability
	// and one committed component.
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       "CVE-2026-0771",
		Summary:     "Widget remote code execution",
		PublishedAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC), Valid: true},
		ModifiedAt:  pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC), Valid: true},
		CpeConfig:   []byte(`[{"nodes":[{"negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"}]}]}]`),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}
	if _, err := svc.CommitInventory(ctx, application.CommitInventoryInput{
		File: []byte(inventoryCSV(inventoryRow("cmdb", "a1", "Portal", "Acme", "Widget", "1.2.3"))),
	}); err != nil {
		t.Fatalf("CommitInventory: %v", err)
	}
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("rebuild drain: %v", err)
	}

	// Enqueue one matching.recompute batch over the vulnerability id (the
	// shape the WP-3.09 incremental path enqueues) and drain it: the
	// handler decodes the batch, resolves the candidate components of the
	// decomposed pairs and commits through the idempotent insert — the
	// stored row count stays one.
	payload := []byte(fmt.Sprintf(`{
		"event_id": "11111111-1111-1111-1111-111111111111",
		"type": "matching.recompute",
		"vulnerability_ids": ["%s"],
		"rule_version": %q,
		"occurred_at": "2026-09-10T00:00:00Z",
		"correlation_id": "corr-065-recompute"
	}`, vulnID.String(), ruleVersion))
	var outboxID pgtype.UUID
	if err := postgres.WithTx(ctx, pool, func(tx pgx.Tx) error {
		row, err := gen.New(pool).WithTx(tx).AppendOutbox(ctx, gen.AppendOutboxParams{
			Type:        application.EventTypeMatchingRecompute,
			Payload:     payload,
			DedupeKey:   application.MatchingRecomputeDedupeKey([]string{vulnID.String()}, "", ruleVersion),
			AvailableAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true},
			CreatedAt:   pgtype.Timestamptz{Time: time.Now(), Valid: true},
		})
		if err != nil {
			return err
		}
		outboxID = row.ID
		return nil
	}); err != nil {
		t.Fatalf("append matching.recompute job: %v", err)
	}

	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("recompute drain: %v", err)
	}
	if n := countMatches(t, ctx, pool, vulnID, componentRowID(t, ctx, q), ruleVersion); n != 1 {
		t.Fatalf("match rows after the recompute batch = %d, want 1 (idempotent overlap with the rebuild row)", n)
	}
	if status := readOutboxStatus(t, ctx, pool, outboxID); status != "done" {
		t.Fatalf("recompute outbox row = %q, want done (no dead-letter)", status)
	}
}

// TestMatchingRuleRepoReadsCurrentRuleset pins the rule-state reads of
// the matching runs against the real schema: the effective alias rules
// are the newest standing enabled row per (scope, from_value) — a newer
// disabled row makes the alias inert — the effective decision rules are
// the unrevoked rules, and the version counters are the monotonic maxima
// of the two tables.
func TestMatchingRuleRepoReadsCurrentRuleset(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)
	repoRules := repo.NewRuleRepo(q)
	at := func() pgtype.Timestamptz {
		return pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC), Valid: true}
	}

	// Alias rules: "ms" → "microsoft" at version 1 (enabled), the same
	// alias remapped at version 2 to a disabled row — the newer row is
	// the standing state of the alias, and disabled means inert.
	if _, err := q.InsertAliasRule(ctx, gen.InsertAliasRuleParams{
		Scope: "vendor", FromValue: "ms", ToValue: "microsoft", Version: 1, Enabled: true,
		Reason: pgtype.Text{String: "t1", Valid: true}, CreatedAt: at(), UpdatedAt: at(),
	}); err != nil {
		t.Fatalf("InsertAliasRule v1: %v", err)
	}
	if _, err := q.InsertAliasRule(ctx, gen.InsertAliasRuleParams{
		Scope: "vendor", FromValue: "ms", ToValue: "microsoft", Version: 2, Enabled: false,
		Reason: pgtype.Text{String: "t2", Valid: true}, CreatedAt: at(), UpdatedAt: at(),
	}); err != nil {
		t.Fatalf("InsertAliasRule v2: %v", err)
	}
	// A standing enabled product alias at version 2.
	if _, err := q.InsertAliasRule(ctx, gen.InsertAliasRuleParams{
		Scope: "product", FromValue: "win", ToValue: "windows", Version: 2, Enabled: true,
		Reason: pgtype.Text{String: "t2", Valid: true}, CreatedAt: at(), UpdatedAt: at(),
	}); err != nil {
		t.Fatalf("InsertAliasRule product: %v", err)
	}

	aliasRules, err := repoRules.EffectiveAliasRules(ctx)
	if err != nil {
		t.Fatalf("EffectiveAliasRules: %v", err)
	}
	if len(aliasRules) != 1 {
		t.Fatalf("effective alias rules = %d, want 1 (the disabled v2 remap is inert, the product alias stands)", len(aliasRules))
	}
	if r := aliasRules[0]; r.Scope != domain.AliasScopeProduct || r.From != "win" || r.To != "windows" || !r.Enabled {
		t.Fatalf("effective alias rule = %+v, want the standing enabled product alias win→windows", r)
	}
	if v, err := repoRules.AliasVersion(ctx); err != nil || v != 2 {
		t.Fatalf("AliasVersion = %d, %v; want 2", v, err)
	}

	// Decision rules: one unrevoked exclude, one revoked override — only
	// the unrevoked rule is effective.
	target := []byte(`{"vendor": "acme", "product": "widget"}`)
	revokedRule, err := q.InsertDecisionRule(ctx, gen.InsertDecisionRuleParams{
		Type: "override", TargetScope: target, Action: []byte(`{"method": "exact_identifier"}`),
		Reason: "revoked soon", ActorID: "it-security", Version: 1, CreatedAt: at(), UpdatedAt: at(),
	})
	if err != nil {
		t.Fatalf("InsertDecisionRule (to revoke): %v", err)
	}
	if _, err := q.RevokeDecisionRule(ctx, gen.RevokeDecisionRuleParams{
		RevokedAt: at(), UpdatedAt: at(), ID: revokedRule,
	}); err != nil {
		t.Fatalf("RevokeDecisionRule: %v", err)
	}
	if _, err := q.InsertDecisionRule(ctx, gen.InsertDecisionRuleParams{
		Type: "exclude", TargetScope: target, Reason: "manual exclusion", ActorID: "it-security",
		Version: 2, CreatedAt: at(), UpdatedAt: at(),
	}); err != nil {
		t.Fatalf("InsertDecisionRule exclude: %v", err)
	}

	decisionRules, err := repoRules.EffectiveDecisionRules(ctx)
	if err != nil {
		t.Fatalf("EffectiveDecisionRules: %v", err)
	}
	if len(decisionRules) != 1 {
		t.Fatalf("effective decision rules = %d, want 1 (the revoked rule is inert)", len(decisionRules))
	}
	if r := decisionRules[0]; r.Type != domain.DecisionRuleTypeExclude || r.Revoked || r.Version != 2 {
		t.Fatalf("effective decision rule = %+v, want the unrevoked version-2 exclude", r)
	}
	if v, err := repoRules.DecisionVersion(ctx); err != nil || v != 2 {
		t.Fatalf("DecisionVersion = %d, %v; want 2", v, err)
	}
}

// TestMatchingReadAdaptersClassifyMissingRows pins the not-found
// classification of the by-id matching reads: an id without a row is a
// torn read, reported not-found — never a silent skip and never an
// infrastructure error.
func TestMatchingReadAdaptersClassifyMissingRows(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)
	missing := "00000000-0000-0000-0000-000000000001"

	if _, err := repo.NewComponentRepo(q).ListComponentsByIDs(ctx, []string{missing}); err == nil {
		t.Fatal("ListComponentsByIDs of a missing id: nil error, want not-found")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("ListComponentsByIDs of a missing id: error kind %s, want not-found", kind)
	}

	if _, err := repo.NewVulnerabilityMatchRepo(q).ListByIDs(ctx, []string{missing}); err == nil {
		t.Fatal("ListByIDs of a missing id: nil error, want not-found")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("ListByIDs of a missing id: error kind %s, want not-found", kind)
	}

	// Empty reads are no-ops, never errors.
	if rows, err := repo.NewComponentRepo(q).ListComponentsPage(ctx, "", 500); err != nil || len(rows) != 0 {
		t.Fatalf("ListComponentsPage on an empty inventory = %d rows, %v; want 0, nil", len(rows), err)
	}
	if rows, err := repo.NewVulnerabilityMatchRepo(q).ListByPairs(ctx, nil); err != nil || len(rows) != 0 {
		t.Fatalf("ListByPairs(nil) = %d rows, %v; want 0, nil", len(rows), err)
	}
	if rows, err := repo.NewVulnerabilityMatchRepo(q).ListByIDs(ctx, nil); err != nil || len(rows) != 0 {
		t.Fatalf("ListByIDs(nil) = %d rows, %v; want 0, nil", len(rows), err)
	}
}
