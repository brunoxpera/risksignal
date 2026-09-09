package main

// Integration test of the WP-3.03b matching/evidence query surface
// (DEV-057, ARCH-003 §3/§7, ADR-013/ADR-015) at the composition root: the
// I3 matches insert — carrying reasons, the referencing decision rule and
// the auto_* override preservation — the matches read by
// (vulnerability_id, component_id) and the append-only epss_history
// insert, all on a real short-lived PostgreSQL. cmd/risksignal is the
// composition root that may wire the embedded migration set
// (db/migrations, including the 00006 contract phase) together with the
// postgres adapter, so the schema and the generated queries are exercised
// here exactly as production wires them.
//
// The test drives the DEV-057 acceptance criterion on real rows:
//
//   - a match row carrying the I3 decision-rule state (reasons jsonb, the
//     decision rule id, auto_method/auto_confidence/auto_score) inserts
//     under its (vulnerability_id, component_id, rule_version) natural
//     key and round-trips through the pair read — reasons decode to the
//     stored list, the rule reference resolves, the preserved auto_*
//     triple survives, and the purely-computed default is jsonb '[]' with
//     no rule and NULL auto_*;
//   - the insert is idempotent on the natural key: the identical write
//     returns the same id and leaves one row (UQ (vulnerability_id,
//     component_id, rule_version), ARCH-003 §3); a later rule version
//     adds a second row and the pair read returns the history newest
//     ruleset first;
//   - the epss_history append (ADR-013, ARCH-003 §7) records one
//     (cve_id, observed_on) day once: re-appending the same day is a
//     no-op (ON CONFLICT (cve_id, observed_on) DO NOTHING), a different
//     cve or a later day appends.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/domain"
)

// TestMatchI3InsertCarriesDecisionRuleStateAndPairRead is the DEV-057
// acceptance test of the matches insert + read: one vulnerability, one
// component, one decision rule and two rule versions of the match pair.
// The first version is an operator-override row: an override rule forced
// the effective exact_identifier triple while the raw computed triple
// stays visible in auto_* (ADR-015, ARCH-003 §3) — exactly the shape the
// matching engine (WP-3.06) persists and the decision-rule survival
// requires. The second version is a purely computed row (reasons '[]',
// no rule, NULL auto_*) of a later ruleset.
func TestMatchI3InsertCarriesDecisionRuleStateAndPairRead(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)
	at := mustTS(t, "2026-09-09T08:00:00Z")

	// Inventory: one asset with one component (I3 write path, natural key
	// derived like the demo seed) and one vulnerability.
	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID:  "asset-i3-match",
		Source:      "demo",
		Type:        "server_vm",
		Name:        "Match Portal",
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
	componentID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID:       assetID,
		Vendor:        "Acme",
		Product:       "Portal",
		Version:       "2.4",
		VendorNorm:    vendorNorm,
		ProductNorm:   productNorm,
		VersionScheme: string(domain.VersionSchemeUnknown),
		NaturalKey:    naturalKey,
		UpdatedAt:     at,
	})
	if err != nil {
		t.Fatalf("InsertComponent: %v", err)
	}
	vulnID, err := q.UpsertVulnerability(ctx, gen.UpsertVulnerabilityParams{
		CveID:       "CVE-2026-9001",
		Summary:     "Portal remote code execution",
		PublishedAt: at,
		ModifiedAt:  at,
	})
	if err != nil {
		t.Fatalf("UpsertVulnerability: %v", err)
	}

	// One override decision rule (ruleset version 1, unrevoked, validity
	// window open): the forced action of the match.
	ruleID, err := q.InsertDecisionRule(ctx, gen.InsertDecisionRuleParams{
		Type:        "override",
		TargetScope: []byte(`{"cve_id": "CVE-2026-9001"}`),
		Action:      []byte(`{"method": "exact_identifier"}`),
		Reason:      "operator verified the affected portal build",
		ActorID:     "it-security",
		Version:     1,
		CreatedAt:   at,
		UpdatedAt:   at,
	})
	if err != nil {
		t.Fatalf("InsertDecisionRule: %v", err)
	}

	// The override match row of ruleset version a1d1: the effective triple
	// is the forced exact_identifier (high, 100) referencing the rule, the
	// raw computed starting point (product_uncertain_version, medium, 65)
	// is preserved in auto_* (ADR-015) and the reasons carry the computed
	// rationale plus the applied rule.
	reasons := []string{"vendor/product norm pair matched", "override rule a1d1 forced exact_identifier"}
	reasonsJSON, err := json.Marshal(reasons)
	if err != nil {
		t.Fatalf("marshal reasons: %v", err)
	}
	matchID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID,
		ComponentID:     componentID,
		Method:          string(domain.MatchMethodExactIdentifier),
		Score:           100,
		Confidence:      string(domain.ConfidenceHigh),
		RuleVersion:     "a1d1",
		CreatedAt:       at,
		Reasons:         reasonsJSON,
		DecisionRuleID:  ruleID,
		AutoMethod:      pgtype.Text{String: string(domain.MatchMethodProductUncertainVersion), Valid: true},
		AutoConfidence:  pgtype.Text{String: string(domain.ConfidenceMedium), Valid: true},
		AutoScore:       pgtype.Int4{Int32: 65, Valid: true},
	})
	if err != nil {
		t.Fatalf("InsertMatch (a1d1): %v", err)
	}
	if !matchID.Valid {
		t.Fatal("InsertMatch returned an invalid id")
	}

	// Idempotency on UQ (vulnerability_id, component_id, rule_version):
	// the identical write returns the canonical match id and leaves one
	// row (ARCH-003 §3 — re-runs never duplicate).
	again, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID,
		ComponentID:     componentID,
		Method:          string(domain.MatchMethodExactIdentifier),
		Score:           100,
		Confidence:      string(domain.ConfidenceHigh),
		RuleVersion:     "a1d1",
		CreatedAt:       at,
		Reasons:         reasonsJSON,
		DecisionRuleID:  ruleID,
		AutoMethod:      pgtype.Text{String: string(domain.MatchMethodProductUncertainVersion), Valid: true},
		AutoConfidence:  pgtype.Text{String: string(domain.ConfidenceMedium), Valid: true},
		AutoScore:       pgtype.Int4{Int32: 65, Valid: true},
	})
	if err != nil || again != matchID {
		t.Fatalf("InsertMatch rerun = %v, %v; want the canonical id %v", again, err, matchID)
	}

	// A purely computed row of a later ruleset (a2d1): reasons '[]', no
	// decision rule, NULL auto_* — the row a rebuild under the next
	// ruleset appends alongside the overridden one.
	later := mustTS(t, "2026-09-09T09:00:00Z")
	computedID, err := q.InsertMatch(ctx, gen.InsertMatchParams{
		VulnerabilityID: vulnID,
		ComponentID:     componentID,
		Method:          string(domain.MatchMethodCanonicalProductRange),
		Score:           80,
		Confidence:      string(domain.ConfidenceHigh),
		RuleVersion:     "a1d2",
		CreatedAt:       later,
		Reasons:         []byte("[]"),
	})
	if err != nil {
		t.Fatalf("InsertMatch (a1d2): %v", err)
	}

	// The pair read returns the full history, newest ruleset first — the
	// a1d2 computed row first, then the a1d1 override row with its full I3
	// state intact.
	rows, err := q.ListMatchesByVulnerabilityComponent(ctx, gen.ListMatchesByVulnerabilityComponentParams{
		VulnerabilityID: vulnID,
		ComponentID:     componentID,
	})
	if err != nil {
		t.Fatalf("ListMatchesByVulnerabilityComponent: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("pair read = %d row(s), want the 2 rule versions", len(rows))
	}
	if rows[0].RuleVersion != "a1d2" || rows[0].ID != computedID {
		t.Fatalf("pair read order = %q (%v) first, want the newer a1d2 row first", rows[0].RuleVersion, rows[0].ID)
	}
	got := rows[1]
	if got.ID != matchID || got.RuleVersion != "a1d1" || !got.CreatedAt.Time.Equal(at.Time) {
		t.Fatalf("pair read a1d1 row = %v/%q/%v, want the override match row", got.ID, got.RuleVersion, got.CreatedAt)
	}
	if got.Method != string(domain.MatchMethodExactIdentifier) || got.Confidence != string(domain.ConfidenceHigh) || got.Score != 100 {
		t.Fatalf("a1d1 effective triple = %s/%s/%d, want exact_identifier/high/100", got.Method, got.Confidence, got.Score)
	}
	var gotReasons []string
	if err := json.Unmarshal(got.Reasons, &gotReasons); err != nil {
		t.Fatalf("decode stored reasons: %v", err)
	}
	if len(gotReasons) != 2 || gotReasons[0] != reasons[0] || gotReasons[1] != reasons[1] {
		t.Fatalf("stored reasons = %v, want %v", gotReasons, reasons)
	}
	if !got.DecisionRuleID.Valid || got.DecisionRuleID != ruleID {
		t.Fatalf("a1d1 decision_rule_id = %v, want the rule %v", got.DecisionRuleID, ruleID)
	}
	if !got.AutoMethod.Valid || got.AutoMethod.String != string(domain.MatchMethodProductUncertainVersion) ||
		!got.AutoConfidence.Valid || got.AutoConfidence.String != string(domain.ConfidenceMedium) ||
		!got.AutoScore.Valid || got.AutoScore.Int32 != 65 {
		t.Fatalf("a1d1 auto_* = %v/%v/%v, want product_uncertain_version/medium/65",
			got.AutoMethod, got.AutoConfidence, got.AutoScore)
	}
	// The purely computed row carries the jsonb '[]' default, no rule and
	// NULL auto_*.
	if string(rows[0].Reasons) != "[]" || rows[0].DecisionRuleID.Valid ||
		rows[0].AutoMethod.Valid || rows[0].AutoConfidence.Valid || rows[0].AutoScore.Valid {
		t.Fatalf("a1d2 computed row state = reasons %s rule %v auto %v/%v/%v, want '[]' and NULLs",
			rows[0].Reasons, rows[0].DecisionRuleID, rows[0].AutoMethod, rows[0].AutoConfidence, rows[0].AutoScore)
	}
	// A pair with no matches reads nothing.
	none, err := q.ListMatchesByVulnerabilityComponent(ctx, gen.ListMatchesByVulnerabilityComponentParams{
		VulnerabilityID: vulnID,
		ComponentID:     assetID, // not a component id — a pair that never matched
	})
	if err != nil || len(none) != 0 {
		t.Fatalf("pair read (no match) = %+v, %v; want no rows", none, err)
	}
}

// TestEpssHistoryAppendIsPerDayIdempotent is the DEV-057 acceptance test
// of the epss_history append (ADR-013, ARCH-003 §7): history rows are
// appended per (cve_id, observed_on) and a repeated append of the same
// day is a no-op — the daily run may re-fire or overlap (the pre-filter
// relevant set can repeat), the history records each observed day exactly
// once.
func TestEpssHistoryAppendIsPerDayIdempotent(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	dayOne := mustDate(t, "2026-09-09")
	dayTwo := mustDate(t, "2026-09-10")
	params := func(cve string, observed pgtype.Date, score, percentile string) gen.AppendEpssHistoryParams {
		var s, p pgtype.Numeric
		if err := s.Scan(score); err != nil {
			t.Fatalf("scan score %q: %v", score, err)
		}
		if err := p.Scan(percentile); err != nil {
			t.Fatalf("scan percentile %q: %v", percentile, err)
		}
		return gen.AppendEpssHistoryParams{
			CveID:        cve,
			ObservedOn:   observed,
			Score:        s,
			Percentile:   p,
			ModelVersion: "2026-09-09",
		}
	}

	// Two relevant cves of the day, then a re-append of one (the loader's
	// ON CONFLICT (cve_id, observed_on) DO NOTHING) and one cve of the
	// next day.
	first := params("CVE-2026-9001", dayOne, "0.85", "0.97")
	second := params("CVE-2026-9002", dayOne, "0.11", "0.32")
	if err := q.AppendEpssHistory(ctx, first); err != nil {
		t.Fatalf("AppendEpssHistory (first): %v", err)
	}
	if err := q.AppendEpssHistory(ctx, second); err != nil {
		t.Fatalf("AppendEpssHistory (second): %v", err)
	}
	if err := q.AppendEpssHistory(ctx, first); err != nil {
		t.Fatalf("AppendEpssHistory re-append: %v", err)
	}
	nextDay := params("CVE-2026-9001", dayTwo, "0.90", "0.98")
	if err := q.AppendEpssHistory(ctx, nextDay); err != nil {
		t.Fatalf("AppendEpssHistory (next day): %v", err)
	}

	var total int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM epss_history").Scan(&total); err != nil {
		t.Fatalf("count epss_history: %v", err)
	}
	if total != 3 {
		t.Fatalf("epss_history rows = %d, want 3 (2 cves of 09-09 + 1 cve of 09-10; re-append is a no-op)", total)
	}
	// The stored day-one row keeps its first-append values.
	var score, percentile string
	if err := pool.QueryRow(ctx, `
		SELECT score::text, percentile::text FROM epss_history
		WHERE cve_id = 'CVE-2026-9001' AND observed_on = '2026-09-09'`).Scan(&score, &percentile); err != nil {
		t.Fatalf("read history row: %v", err)
	}
	if score != "0.85" || percentile != "0.97" {
		t.Fatalf("history row = %s/%s, want 0.85/0.97 (first append wins)", score, percentile)
	}
}

// mustDate builds a valid pgtype.Date for the fixed test day.
func mustDate(t *testing.T, s string) pgtype.Date {
	t.Helper()
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		t.Fatalf("parse date %q: %v", s, err)
	}
	return pgtype.Date{Time: d, Valid: true}
}
