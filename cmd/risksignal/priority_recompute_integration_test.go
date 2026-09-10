package main

// Integration test of the DEV-077 priority-rules publish + priority recompute
// (ARCH-004 §1/§5) at the composition root: the use cases run against a real,
// short-lived PostgreSQL behind the production postgres repositories and
// postgres.WithTx, exactly as the I5b root wires them. It proves that
//
//   - PublishPriorityRules writes a full P1..P4 snapshot at MAX(version)+1
//     (the migration seeds version 1, so the publish lands at 2), and
//   - RecomputePriority rebuilds the factors from persisted evidence and
//     persists the changed result — priority, rule_version and factors reach
//     the database, and a second identical recompute writes nothing.
//
// The database server is the compose `db` service (make up) or any
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; the test skips
// when none is reachable (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
)

// seedVulnEvidence writes the factor evidence of the fixture vulnerability:
// a high-confidence-but-not-urgent set (KEV false, CVSS 5.0, EPSS 0.1) so a
// recompute resolves the signal to P3 — different from the P1 the CreateSignal
// input stamped.
func seedVulnEvidence(t *testing.T, pool *pgxpool.Pool, at time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var sourceID, rawID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO sources (type, name) VALUES ('nvd', 'it-priority') RETURNING id`).Scan(&sourceID); err != nil {
		t.Fatalf("insert source: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO raw_records (source_id, external_id, content_hash, payload, fetched_at)
		 VALUES ($1, 'nvd:it-priority', 'hash-it-priority', convert_to('{}', 'UTF8'), $2) RETURNING id`,
		sourceID, at).Scan(&rawID); err != nil {
		t.Fatalf("insert raw record: %v", err)
	}

	evidence := []struct{ typ, value string }{
		{"cvss", `{"cve_id":"` + faultTestCveID + `","base_score":5.0}`},
		{"kev", `{"cve_id":"` + faultTestCveID + `","known_exploited":false}`},
		{"epss", `{"cve_id":"` + faultTestCveID + `","percentile":0.1}`},
	}
	for _, e := range evidence {
		if _, err := pool.Exec(ctx,
			`INSERT INTO evidences (vulnerability_id, raw_record_id, type, value, value_hash, observed_at)
			 SELECT v.id, $1, $2, $3::jsonb, $4, $5 FROM vulnerabilities v WHERE v.cve_id = $6`,
			rawID, e.typ, e.value, "hash-"+e.typ, at, faultTestCveID); err != nil {
			t.Fatalf("insert %s evidence: %v", e.typ, err)
		}
	}
}

// readSignalRecompute reads back the recomputed columns of one signal.
func readSignalRecompute(t *testing.T, pool *pgxpool.Pool, signalID string) (priority, ruleVersion string, factors []byte, version int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.QueryRow(ctx,
		`SELECT priority, rule_version, factors, version FROM risk_signals WHERE id = $1`, signalID).
		Scan(&priority, &ruleVersion, &factors, &version); err != nil {
		t.Fatalf("read signal: %v", err)
	}
	return priority, ruleVersion, factors, version
}

// TestPriorityRulesPublishAndRecomputePersist drives a publish and a recompute
// against a real database and asserts both persist (the DEV-077 acceptance
// criterion).
func TestPriorityRulesPublishAndRecomputePersist(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	at := triageClockTime
	clk := clock.NewFakeClock(at)
	matchID := seedCreateSignalFixture(t, pool, at)
	seedVulnEvidence(t, pool, at)
	svc := newTriageService(pool, clk)

	created, err := svc.CreateSignal(ctx, faultTestInput(matchID))
	if err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	sig := created.Signal
	if sig.Priority != domain.PriorityP1 {
		t.Fatalf("signal priority = %s, want P1", sig.Priority)
	}

	// 1. Publish a new snapshot: the migration seeded version 1, so this
	// lands at version 2 with four rows.
	pub, err := svc.PublishPriorityRules(ctx, application.PublishPriorityRulesInput{
		Reason: "integration publish",
		Actor:  p1TestActor,
	})
	if err != nil {
		t.Fatalf("PublishPriorityRules: %v", err)
	}
	if pub.Version != 2 || pub.RuleVersion != "p0000000002" {
		t.Fatalf("publish = %+v, want version 2 / p0000000002", pub)
	}
	var snapRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM priority_rules WHERE version = 2`).Scan(&snapRows); err != nil {
		t.Fatalf("count snapshot rows: %v", err)
	}
	if snapRows != 4 {
		t.Fatalf("snapshot rows at version 2 = %d, want 4", snapRows)
	}

	// 2. Recompute: the rebuilt factors resolve to P3 and the rule version
	// moved to p0000000002 — the change persists.
	res, err := svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: sig.ID, Actor: p1TestActor})
	if err != nil {
		t.Fatalf("RecomputePriority: %v", err)
	}
	if !res.Changed || res.Priority != domain.PriorityP3 {
		t.Fatalf("recompute = %+v, want Changed P3", res)
	}
	priority, ruleVersion, factors, version := readSignalRecompute(t, pool, sig.ID)
	if priority != string(domain.PriorityP3) || ruleVersion != "p0000000002" {
		t.Fatalf("stored = %s/%s, want P3/p0000000002", priority, ruleVersion)
	}
	if version != sig.Version+1 {
		t.Fatalf("stored version = %d, want %d", version, sig.Version+1)
	}
	var rebuilt struct {
		KEV  bool    `json:"kev"`
		CVSS float64 `json:"cvss"`
	}
	if err := json.Unmarshal(factors, &rebuilt); err != nil {
		t.Fatalf("decode stored factors: %v", err)
	}
	if rebuilt.KEV || rebuilt.CVSS != 5.0 {
		t.Fatalf("stored factors = %s, want the rebuilt KEV=false CVSS=5.0 set", factors)
	}

	// 3. Re-run over the unchanged input: changed-only persist writes nothing.
	res2, err := svc.RecomputePriority(ctx, application.RecomputePriorityInput{SignalID: sig.ID, Actor: p1TestActor})
	if err != nil {
		t.Fatalf("RecomputePriority (rerun): %v", err)
	}
	if res2.Changed {
		t.Fatal("rerun reported Changed, want a no-op")
	}
	if _, _, _, version2 := readSignalRecompute(t, pool, sig.ID); version2 != version {
		t.Fatalf("rerun bumped version to %d, want unchanged %d", version2, version)
	}
}
