package application_test

// Unit tests of the WP-3.08 matching-run core (DEV-063, ARCH-003 §3/§5):
// RunMatching evaluates every candidate of a batch through the pure
// matching engine (matching.Evaluate — the decision rules of the
// candidate's ruleset are applied there) and writes the outcomes as
// method-led matches through the MatchRepo port, in bounded transactions
// of matchingBatchSize (500). The tests drive the DEV-063 acceptance
// criteria on the fake persistence:
//
//   - idempotency: a re-run of the same batch under the same ruleset
//     yields the same matches and no duplicate rows (the UQ
//     (vulnerability_id, component_id, rule_version) insert semantics the
//     fake MatchRepo mirrors from the generated InsertMatch);
//   - decision-rules applied: an exclude outcome is stored as a visible
//     no_match referencing the rule and an override outcome as the forced
//     method with the raw computed triple preserved in the auto_* fields;
//   - batching: a batch is processed in transactions of 500 candidates
//     (incremental commit), an empty batch is a no-op and a failing
//     candidate rolls back its whole transaction.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/matching"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// matchRunNow is the clock instant the decision-rule validity windows of
// the fixtures are evaluated against (open-ended rules apply at any
// instant; the instant is pinned for reproducibility, matching the engine
// tests).
var matchRunNow = time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

// matchRunComponent assembles one semver component of the fixtures — the
// vendor/product fallback identity with the write-time folded comparison
// keys, like the I3 write path stores it.
func matchRunComponent(id string) domain.Component {
	c, err := domain.NewComponent(id, "asset-matchrun", domain.ComponentIdentifiers{
		Vendor:  "acme",
		Product: "widget",
		Version: "1.5.0",
	}, "acme", "widget", "", domain.VersionSchemeSemver)
	if err != nil {
		panic(err)
	}
	return c
}

// matchRunStatement is the affected-product statement of the fixtures: the
// canonical product pair of the fixture component with an affected window
// of [1.0, 2.0) — the fixture version 1.5.0 lies inside it.
func matchRunStatement() matching.AffectedProduct {
	return matching.AffectedProduct{
		Vendor:  "acme",
		Product: "widget",
		Ranges:  []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}},
	}
}

// matchRunCandidate assembles one candidate: the persisted vulnerability
// row id, the component id and the full engine input under the given
// ruleset counters and decision rules.
func matchRunCandidate(vulnID, compID string, aliasVersion, decisionVersion int, rules []domain.DecisionRule) application.MatchCandidate {
	return application.MatchCandidate{
		VulnerabilityID: vulnID,
		Evaluation: matching.Input{
			CVEID:           "CVE-2026-0001",
			Statements:      []matching.AffectedProduct{matchRunStatement()},
			Component:       matchRunComponent(compID),
			DecisionRules:   rules,
			AliasVersion:    aliasVersion,
			DecisionVersion: decisionVersion,
			Now:             matchRunNow,
		},
	}
}

// mustMatchRunRule assembles one decision rule of the fixtures or fails
// the test (version 2 — the ruleset the decision-rule tests evaluate
// under).
func mustMatchRunRule(t *testing.T, typ domain.DecisionRuleType, target domain.DecisionTarget, action *domain.DecisionAction) domain.DecisionRule {
	t.Helper()
	r, err := domain.NewDecisionRule("dr-"+string(typ), typ, target, action,
		"manual correction: unit fixture", "alice", 2, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("NewDecisionRule: unexpected error: %v", err)
	}
	return r
}

// storedMatchByVuln returns the stored match row of one vulnerability id.
func storedMatchByVuln(t *testing.T, h *harness, vulnID string) storedMatch {
	t.Helper()
	for _, m := range h.db.matchRows {
		if m.rec.VulnerabilityID == vulnID {
			return m
		}
	}
	t.Fatalf("no stored match for vulnerability %s", vulnID)
	return storedMatch{}
}

// matchOps counts the InsertMatch calls recorded on one fake transaction.
func matchOps(tx *fakeTx) int {
	n := 0
	for _, op := range tx.log {
		if op == "match" {
			n++
		}
	}
	return n
}

// TestRunMatchingComputesAndWritesMethodLedMatches: a batch of two
// candidates under ruleset (1, 1) is evaluated and written in one
// transaction — the affected pair as canonical_product_range/high/80 and
// the provably-not-affected pair as a stored no_match/none/0 — each with
// the derived composite rule_version and the auditable reasons.
func TestRunMatchingComputesAndWritesMethodLedMatches(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	outside := matchRunComponent("comp-outside")
	outside.Version = "3.0" // provably outside the [1.0, 2.0) window → no_match
	batch := []application.MatchCandidate{
		matchRunCandidate("vuln-affected", "comp-affected", 1, 1, nil),
		{
			VulnerabilityID: "vuln-outside",
			Evaluation: matching.Input{
				CVEID:      "CVE-2026-0001",
				Statements: []matching.AffectedProduct{matchRunStatement()},
				Component:  outside,
			},
		},
	}

	res, err := h.svc.RunMatching(ctx, batch)
	if err != nil {
		t.Fatalf("RunMatching: unexpected error: %v", err)
	}
	if res.Candidates != 2 || res.Transactions != 1 {
		t.Fatalf("RunMatching result = %+v, want 2 candidates in 1 transaction", res)
	}
	if len(h.runner.txs) != 1 || !h.runner.txs[0].committed || h.runner.txs[0].rolledBack {
		t.Fatalf("transactions = %d (committed=%v rolledBack=%v), want exactly one committed transaction",
			len(h.runner.txs), len(h.runner.txs) > 0 && h.runner.txs[0].committed, len(h.runner.txs) > 0 && h.runner.txs[0].rolledBack)
	}
	if n := len(h.db.matchRows); n != 2 {
		t.Fatalf("committed match rows = %d, want 2", n)
	}

	ruleVersion, err := domain.RulesetVersion(1, 1)
	if err != nil {
		t.Fatalf("RulesetVersion: %v", err)
	}
	affected := storedMatchByVuln(t, h, "vuln-affected")
	if affected.rec.Method != domain.MatchMethodCanonicalProductRange ||
		affected.rec.Confidence != domain.ConfidenceHigh || affected.rec.Score != 80 {
		t.Errorf("affected match = %s/%s/%d, want canonical_product_range/high/80",
			affected.rec.Method, affected.rec.Confidence, affected.rec.Score)
	}
	if affected.rec.ComponentID != "comp-affected" {
		t.Errorf("affected match component_id = %q, want comp-affected", affected.rec.ComponentID)
	}
	if affected.rec.RuleVersion != ruleVersion {
		t.Errorf("affected match rule_version = %q, want the derived %q", affected.rec.RuleVersion, ruleVersion)
	}
	if len(affected.rec.Reasons) == 0 {
		t.Error("affected match reasons empty, want the auditable TR-007 evidence")
	}
	if affected.rec.DecisionRuleID != nil || affected.rec.AutoMethod != nil || affected.rec.AutoConfidence != nil || affected.rec.AutoScore != nil {
		t.Errorf("affected match decision state = %v/%v/%v/%v, want all nil (purely computed)",
			affected.rec.DecisionRuleID, affected.rec.AutoMethod, affected.rec.AutoConfidence, affected.rec.AutoScore)
	}
	if !affected.createdAt.Equal(fixedNow) {
		t.Errorf("affected match created_at = %v, want the injected clock %v", affected.createdAt, fixedNow)
	}

	outsideMatch := storedMatchByVuln(t, h, "vuln-outside")
	if outsideMatch.rec.Method != domain.MatchMethodNoMatch ||
		outsideMatch.rec.Confidence != domain.ConfidenceNone || outsideMatch.rec.Score != 0 {
		t.Errorf("outside match = %s/%s/%d, want the stored no_match/none/0 of the provably-not-affected pair",
			outsideMatch.rec.Method, outsideMatch.rec.Confidence, outsideMatch.rec.Score)
	}
	if len(outsideMatch.rec.Reasons) == 0 {
		t.Error("outside match reasons empty, want the provable-negative evidence")
	}
}

// TestRunMatchingIsIdempotentAcrossRuns is the DEV-063 idempotency
// acceptance test: re-running the same batch under the same ruleset is a
// no-op at the data level — every pair resolves to the same canonical
// match row and no row duplicates (the UQ (vulnerability_id, component_id,
// rule_version) insert semantics of InsertMatch, mirrored by the fake
// MatchRepo).
func TestRunMatchingIsIdempotentAcrossRuns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	batch := []application.MatchCandidate{
		matchRunCandidate("vuln-a", "comp-a", 1, 1, nil),
		matchRunCandidate("vuln-b", "comp-b", 1, 1, nil),
	}

	first, err := h.svc.RunMatching(ctx, batch)
	if err != nil {
		t.Fatalf("RunMatching (first run): unexpected error: %v", err)
	}
	second, err := h.svc.RunMatching(ctx, batch)
	if err != nil {
		t.Fatalf("RunMatching (re-run): unexpected error: %v", err)
	}
	if first != second {
		t.Fatalf("re-run result = %+v, want the first run's %+v", second, first)
	}
	if n := len(h.db.matchRows); n != 2 {
		t.Fatalf("committed match rows after the re-run = %d, want 2 (no duplicates)", n)
	}
	// The re-run resolved the same canonical rows: same ids, same records,
	// same injected-clock created_at (the re-run wrote nothing new).
	for _, m := range h.db.matchRows {
		switch m.rec.VulnerabilityID {
		case "vuln-a", "vuln-b":
		default:
			t.Fatalf("stored match references unexpected vulnerability %q", m.rec.VulnerabilityID)
		}
		if !m.createdAt.Equal(fixedNow) {
			t.Errorf("match %s created_at = %v, want the injected clock %v", m.rec.VulnerabilityID, m.createdAt, fixedNow)
		}
	}
}

// TestRunMatchingStoresDecisionRuleOutcomes is the DEV-063 decision-rules
// acceptance test: the engine applies the decision rules of the
// candidate's ruleset (ARCH-003 §3, ADR-015) and RunMatching stores the
// resulting outcome — an exclude as a visible no_match that references the
// rule (no auto_* — only an override preserves the computed starting
// point) and an override as the forced method with the raw computed triple
// preserved in auto_* — both under the ruleset version the decision rule
// belongs to.
func TestRunMatchingStoresDecisionRuleOutcomes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	excludeRule := mustMatchRunRule(t, domain.DecisionRuleTypeExclude,
		domain.DecisionTarget{CVEID: "CVE-2026-0001", Product: "widget"}, nil)
	overrideRule := mustMatchRunRule(t, domain.DecisionRuleTypeOverride,
		domain.DecisionTarget{CVEID: "CVE-2026-0001"},
		&domain.DecisionAction{Method: domain.MatchMethodExactIdentifier})

	batch := []application.MatchCandidate{
		matchRunCandidate("vuln-excluded", "comp-excluded", 1, 2, []domain.DecisionRule{excludeRule}),
		matchRunCandidate("vuln-overridden", "comp-overridden", 1, 2, []domain.DecisionRule{overrideRule}),
	}
	if _, err := h.svc.RunMatching(ctx, batch); err != nil {
		t.Fatalf("RunMatching: unexpected error: %v", err)
	}

	ruleVersion, err := domain.RulesetVersion(1, 2)
	if err != nil {
		t.Fatalf("RulesetVersion: %v", err)
	}

	excluded := storedMatchByVuln(t, h, "vuln-excluded")
	if excluded.rec.Method != domain.MatchMethodNoMatch ||
		excluded.rec.Confidence != domain.ConfidenceNone || excluded.rec.Score != 0 {
		t.Errorf("exclude match = %s/%s/%d, want the rule-forced no_match/none/0",
			excluded.rec.Method, excluded.rec.Confidence, excluded.rec.Score)
	}
	if excluded.rec.DecisionRuleID == nil || *excluded.rec.DecisionRuleID != excludeRule.ID {
		t.Errorf("exclude match decision_rule_id = %v, want %q (the exclusion must reference the rule)",
			excluded.rec.DecisionRuleID, excludeRule.ID)
	}
	if excluded.rec.AutoMethod != nil || excluded.rec.AutoConfidence != nil || excluded.rec.AutoScore != nil {
		t.Error("exclude match must not set auto_* (only an override preserves the raw triple)")
	}
	if len(excluded.rec.Reasons) == 0 || excluded.rec.Reasons[len(excluded.rec.Reasons)-1] != "excluded by decision rule "+excludeRule.ID+": manual correction: unit fixture" {
		t.Errorf("exclude match reasons = %v, want the computed reasons plus the exclusion note", excluded.rec.Reasons)
	}
	if excluded.rec.RuleVersion != ruleVersion {
		t.Errorf("exclude match rule_version = %q, want the ruleset of the decision rule %q", excluded.rec.RuleVersion, ruleVersion)
	}

	overridden := storedMatchByVuln(t, h, "vuln-overridden")
	if overridden.rec.Method != domain.MatchMethodExactIdentifier ||
		overridden.rec.Confidence != domain.ConfidenceHigh || overridden.rec.Score != 100 {
		t.Errorf("override match = %s/%s/%d, want the forced exact_identifier/high/100",
			overridden.rec.Method, overridden.rec.Confidence, overridden.rec.Score)
	}
	if overridden.rec.DecisionRuleID == nil || *overridden.rec.DecisionRuleID != overrideRule.ID {
		t.Errorf("override match decision_rule_id = %v, want %q", overridden.rec.DecisionRuleID, overrideRule.ID)
	}
	if overridden.rec.AutoMethod == nil || *overridden.rec.AutoMethod != domain.MatchMethodCanonicalProductRange ||
		overridden.rec.AutoConfidence == nil || *overridden.rec.AutoConfidence != domain.ConfidenceHigh ||
		overridden.rec.AutoScore == nil || *overridden.rec.AutoScore != 80 {
		t.Errorf("override match auto_* = %v/%v/%v, want the raw canonical_product_range/high/80 triple",
			overridden.rec.AutoMethod, overridden.rec.AutoConfidence, overridden.rec.AutoScore)
	}
	if overridden.rec.RuleVersion != ruleVersion {
		t.Errorf("override match rule_version = %q, want the ruleset of the decision rule %q", overridden.rec.RuleVersion, ruleVersion)
	}
}

// TestRunMatchingProcessesBatchesOfFiveHundred: ARCH-003 §5 incremental
// commit — a candidate list larger than one transaction's bound spans
// several committed transactions (500 per transaction), so a long run
// commits progress in bounded steps. An empty batch is a no-op: no
// transaction, zero result.
func TestRunMatchingProcessesBatchesOfFiveHundred(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	empty, err := h.svc.RunMatching(ctx, nil)
	if err != nil {
		t.Fatalf("RunMatching (empty batch): unexpected error: %v", err)
	}
	if empty != (application.RunMatchingResult{}) {
		t.Fatalf("empty batch result = %+v, want the zero result", empty)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("empty batch opened %d transaction(s), want none", len(h.runner.txs))
	}

	batch := make([]application.MatchCandidate, 0, 501)
	for i := 0; i < 501; i++ {
		batch = append(batch, matchRunCandidate(fmt.Sprintf("vuln-%03d", i), fmt.Sprintf("comp-%03d", i), 1, 1, nil))
	}

	res, err := h.svc.RunMatching(ctx, batch)
	if err != nil {
		t.Fatalf("RunMatching (501 candidates): unexpected error: %v", err)
	}
	if res.Candidates != 501 || res.Transactions != 2 {
		t.Fatalf("RunMatching result = %+v, want 501 candidates in 2 transactions", res)
	}
	if len(h.runner.txs) != 2 {
		t.Fatalf("transactions = %d, want 2", len(h.runner.txs))
	}
	if ops := matchOps(h.runner.txs[0]); ops != 500 {
		t.Fatalf("first transaction wrote %d matches, want 500", ops)
	}
	if ops := matchOps(h.runner.txs[1]); ops != 1 {
		t.Fatalf("second transaction wrote %d matches, want 1", ops)
	}
	if !h.runner.txs[0].committed || !h.runner.txs[1].committed {
		t.Fatal("both transactions must commit (incremental progress)")
	}
	if n := len(h.db.matchRows); n != 501 {
		t.Fatalf("committed match rows = %d, want 501", n)
	}
}

// TestRunMatchingRollsBackTheBatchOnEvaluationError: a candidate the
// engine rejects (a statement naming no product identity) aborts its whole
// transaction — the healthy candidates of the same batch are rolled back
// with it, no partial batch state (TR-004 / fault-injection criterion (i)
// at the batch level).
func TestRunMatchingRollsBackTheBatchOnEvaluationError(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	bad := matchRunCandidate("vuln-bad", "comp-bad", 1, 1, nil)
	bad.Evaluation.Statements = []matching.AffectedProduct{{}} // no identity → engine error
	batch := []application.MatchCandidate{
		matchRunCandidate("vuln-good", "comp-good", 1, 1, nil),
		bad,
	}

	_, err := h.svc.RunMatching(ctx, batch)
	if err == nil {
		t.Fatal("RunMatching with a malformed candidate succeeded, want an error")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("error kind = %s, want validation", kind)
	}
	if len(h.runner.txs) != 1 || !h.runner.txs[0].rolledBack || h.runner.txs[0].committed {
		t.Fatalf("transactions after the failure = %d (committed=%v rolledBack=%v), want one rolled-back transaction",
			len(h.runner.txs), len(h.runner.txs) > 0 && h.runner.txs[0].committed, len(h.runner.txs) > 0 && h.runner.txs[0].rolledBack)
	}
	if n := len(h.db.matchRows); n != 0 {
		t.Fatalf("committed match rows after the rollback = %d, want 0 (no partial batch state)", n)
	}
}
