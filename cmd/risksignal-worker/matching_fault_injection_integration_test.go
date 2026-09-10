package main

// Integration test of the WP-3.11 fault-injection exit criterion, cases (ii)
// and (iii) (DEV-054, ARCH-003 §8, TR-012): the at-least-once delivery of the
// matching.rebuild job has no double effect, and re-running the rebuild over
// the same (rule_version, inventory_snapshot) is idempotent. cmd/risksignal-worker
// is the composition root that wires the embedded migration set with the
// postgres adapter, the worker relay and the matching job handlers, so the
// full chain (outbox claim → matching.rebuild handler → RunMatching → matches
// UQ) is exercised against a real, short-lived PostgreSQL.
//
//   (ii) a worker claims the rebuild job and computes the matches, then
//        crashes before the ack: the row sits 'claimed' with an expired
//        lease. The next drain re-claims it (attempts + 1), the handler
//        re-runs the rebuild and acks — the match rows are byte-identical to
//        the pre-crash run (UQ (vulnerability_id, component_id, rule_version)
//        absorbs the re-run), so the redelivery has no double effect.
//   (iii) running matching.rebuild twice with the same rule_version and
//        inventory_snapshot stores one match row per pair and the second run
//        leaves that row byte-identical — zero duplicates.
//
// The tests use the deterministic composition of the WP-3.08/3.09 matching
// pipeline (the same wiring as the rebuild-drain acceptance test); they skip
// when no PostgreSQL is reachable.

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xpera/risksignal/internal/adapters/postgres"
	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/adapters/worker"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/platform/clock"
)

// newMatchingWorkerStack wires the DEV-065 matching pipeline at the worker
// composition root: the application service (the matching core) over the
// postgres repos, the relay with the matching.rebuild / matching.recompute
// handlers registered, and the matching runner they drive. The injected clock
// is the service's (match created_at) and the runner's (decision windows).
func newMatchingWorkerStack(t *testing.T, pool *pgxpool.Pool, clk clock.Clock) (*application.Service, *worker.Relay, *application.MatchingRunner) {
	t.Helper()
	q := gen.New(pool)
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
		Clock:           clk,
		RunTx: func(ctx context.Context, fn func(tx application.Tx) error) error {
			return postgres.WithTx(ctx, pool, fn)
		},
	})
	relay, err := worker.NewRelay(repo.NewOutboxRelay(q), discardLogger())
	if err != nil {
		t.Fatalf("worker.NewRelay: %v", err)
	}
	runner, err := application.NewMatchingRunner(svc,
		repo.NewRuleRepo(q), repo.NewComponentRepo(q), repo.NewVulnerabilityMatchRepo(q), clk, discardLogger())
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
	return svc, relay, runner
}

// matchingFixtureVulnerability seeds one vulnerability whose stored NVD
// configurations block names an affected Acme Widget version window.
func matchingFixtureVulnerability(t *testing.T, ctx context.Context, q *gen.Queries, cve string) pgtype.UUID {
	t.Helper()
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       cve,
		Summary:     "Widget remote code execution",
		PublishedAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC), Valid: true},
		ModifiedAt:  pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 8, 0, 0, 0, time.UTC), Valid: true},
		CpeConfig:   []byte(`[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"}]}]}]`),
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}
	return vulnID
}

// TestMatchingRebuildCrashAfterClaimReclaimsWithNoDoubleEffect is case (ii):
// a worker claims the rebuild, computes the matches, crashes before the ack;
// the expired lease redelivers the job, the rebuild re-runs and the match
// rows are unchanged — no double effect (TR-012).
func TestMatchingRebuildCrashAfterClaimReclaimsWithNoDoubleEffect(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	q := gen.New(pool)

	svc, relay, runner := newMatchingWorkerStack(t, pool, clock.RealClock{})
	vulnID := matchingFixtureVulnerability(t, ctx, q, "CVE-2026-3001")

	// The inventory commit enqueues exactly one matching.rebuild job.
	commit, err := svc.CommitInventory(ctx, application.CommitInventoryInput{
		File: []byte(inventoryCSV(inventoryRow("cmdb", "a1", "Portal", "Acme", "Widget", "1.2.3"))),
	})
	if err != nil {
		t.Fatalf("CommitInventory: %v", err)
	}
	var jobID pgtype.UUID
	if err := pool.QueryRow(ctx,
		"SELECT id FROM outbox WHERE type = 'matching.rebuild'").Scan(&jobID); err != nil {
		t.Fatalf("read rebuild job id: %v", err)
	}
	compID := componentRowID(t, ctx, q)

	// A worker claims the job (attempts 1) and runs the rebuild, then crashes
	// before the ack: the row stays 'claimed' with a live lease.
	claimed, err := q.ClaimOutboxBatch(ctx, 50)
	if err != nil {
		t.Fatalf("ClaimOutboxBatch: %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != jobID {
		t.Fatalf("ClaimOutboxBatch = %+v, want exactly the rebuild job %v", claimed, jobID)
	}
	if _, err := runner.RebuildMatching(ctx, application.RebuildMatchingInput{
		RuleVersion: commit.RuleVersion, InventorySnapshot: commit.InventorySnapshot,
	}); err != nil {
		t.Fatalf("RebuildMatching (pre-crash): %v", err)
	}
	if n := countMatches(t, ctx, pool, vulnID, compID, commit.RuleVersion); n != 1 {
		t.Fatalf("matches after the pre-crash rebuild = %d, want 1", n)
	}
	if status := readOutboxStatus(t, ctx, pool, jobID); status != "claimed" {
		t.Fatalf("job status before the lease expires = %q, want claimed (crash before the ack)", status)
	}
	before := snapshotMatching(t, ctx, pool, vulnID, compID, commit.RuleVersion)

	// The crash: the lease expires (forced SQL-side, as time would).
	if _, err := pool.Exec(ctx,
		"UPDATE outbox SET lease_until = now() - interval '1 second' WHERE id = $1", jobID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	// The next drain re-claims (attempts + 1), the handler re-runs the rebuild
	// and acks. The match rows are identical — the re-run had no double effect.
	if err := relay.Drain(ctx); err != nil {
		t.Fatalf("reclaim drain: %v", err)
	}
	if n := countMatches(t, ctx, pool, vulnID, compID, commit.RuleVersion); n != 1 {
		t.Fatalf("matches after the reclaimed rebuild = %d, want still 1 (no double effect)", n)
	}
	if status := readOutboxStatus(t, ctx, pool, jobID); status != "done" {
		t.Fatalf("job status after the reclaimed drain = %q, want done", status)
	}
	var attempts int
	if err := pool.QueryRow(ctx, "SELECT attempts FROM outbox WHERE id = $1", jobID).Scan(&attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("job attempts = %d, want 2 (the lease expiry counts as a redelivery)", attempts)
	}
	after := snapshotMatching(t, ctx, pool, vulnID, compID, commit.RuleVersion)
	if before != after {
		t.Fatalf("match row changed across the reclaimed rebuild:\n before %s\n after  %s", before, after)
	}
	var deadLetters int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE status = 'dead_letter'").Scan(&deadLetters); err != nil {
		t.Fatalf("count dead-lettered rows: %v", err)
	}
	if deadLetters != 0 {
		t.Fatalf("dead-lettered outbox rows = %d, want 0", deadLetters)
	}
}

// TestMatchingRebuildTwiceIdenticalMatchesNoDuplicates is case (iii): running
// matching.rebuild twice with the same (rule_version, inventory_snapshot)
// leaves one match row per pair and the second run writes nothing new.
func TestMatchingRebuildTwiceIdenticalMatchesNoDuplicates(t *testing.T) {
	pool := newMigratedWorkerPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	q := gen.New(pool)
	clk := clock.NewFakeClock(time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC))

	svc, _, runner := newMatchingWorkerStack(t, pool, clk)
	vulnID := matchingFixtureVulnerability(t, ctx, q, "CVE-2026-3002")

	commit, err := svc.CommitInventory(ctx, application.CommitInventoryInput{
		File: []byte(inventoryCSV(inventoryRow("cmdb", "a1", "Portal", "Acme", "Widget", "1.2.3"))),
	})
	if err != nil {
		t.Fatalf("CommitInventory: %v", err)
	}
	compID := componentRowID(t, ctx, q)

	in := application.RebuildMatchingInput{RuleVersion: commit.RuleVersion, InventorySnapshot: commit.InventorySnapshot}
	if _, err := runner.RebuildMatching(ctx, in); err != nil {
		t.Fatalf("RebuildMatching (run 1): %v", err)
	}
	if n := countMatches(t, ctx, pool, vulnID, compID, commit.RuleVersion); n != 1 {
		t.Fatalf("matches after run 1 = %d, want 1", n)
	}
	first := snapshotMatching(t, ctx, pool, vulnID, compID, commit.RuleVersion)

	if _, err := runner.RebuildMatching(ctx, in); err != nil {
		t.Fatalf("RebuildMatching (run 2): %v", err)
	}
	if n := countMatches(t, ctx, pool, vulnID, compID, commit.RuleVersion); n != 1 {
		t.Fatalf("matches after run 2 = %d, want still 1 (zero duplicates)", n)
	}
	second := snapshotMatching(t, ctx, pool, vulnID, compID, commit.RuleVersion)
	if first != second {
		t.Fatalf("the double rebuild produced a different match row:\n run1 %s\n run2 %s", first, second)
	}
}

// snapshotMatching reads the full observable shape of the fixture pair's single
// match row (including the id and created_at), so a double run can be compared
// byte-for-byte.
func snapshotMatching(t *testing.T, ctx context.Context, pool *pgxpool.Pool, vulnID, compID pgtype.UUID, ruleVersion string) string {
	t.Helper()
	var (
		id, method, confidence, rv string
		score                      int
		reasons                    []byte
		decisionRuleID             pgtype.UUID
		autoMethod, autoConfidence pgtype.Text
		autoScore                  pgtype.Int4
		createdAt                  time.Time
	)
	if err := pool.QueryRow(ctx,
		`SELECT id, method, confidence, score, rule_version, reasons,
		        decision_rule_id, auto_method, auto_confidence, auto_score, created_at
		 FROM matches WHERE vulnerability_id = $1 AND component_id = $2 AND rule_version = $3`,
		vulnID, compID, ruleVersion).Scan(
		&id, &method, &confidence, &score, &rv, &reasons,
		&decisionRuleID, &autoMethod, &autoConfidence, &autoScore, &createdAt); err != nil {
		t.Fatalf("snapshot match row: %v", err)
	}
	return id + "|" + method + "|" + confidence + "|" + rv + "|" +
		strconv.Itoa(score) + "|" + string(reasons) + "|" +
		fmt.Sprintf("%v", decisionRuleID) + "|" + fmt.Sprintf("%v", autoMethod) + "|" +
		fmt.Sprintf("%v", autoConfidence) + "|" + fmt.Sprintf("%v", autoScore) + "|" + createdAt.UTC().Format(time.RFC3339Nano)
}
