package application_test

// Unit tests of the WP-3.08 matching.recompute run (DEV-064, ARCH-003
// §5, ADR-012): the pre-filtered CVE batch job — per CVE of the batch
// (≤500 ids), the candidate components are resolved through the WP-3.07
// candidate pre-filter (CandidateComponentIDs over the inventory product
// index, alias closure included) and the assembled candidates are
// committed through the DEV-063 RunMatching core. The tests drive the
// DEV-064 acceptance criteria on the fake persistence:
//
//   - a pre-filtered batch produces the matches of exactly the CVEs with
//     candidate components — a CVE without candidates spawns no work;
//   - re-running the same batch (same dedupe key: hash of the sorted id
//     list + component_scope + rule_version) yields identical matches and
//     no duplicates; batch order and duplicate ids do not matter;
//   - the dedupe key contract: order-independent, set-sensitive, scoped.
//
// The fake read ports are shared with the rebuild tests
// (matching_rebuild_test.go); the RunMatching core is the real
// application service over the shared fake persistence.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/matching"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// newRecomputeEnv wires the fakes plus the real application service core,
// sharing the fixture helpers of the rebuild tests.
func newRecomputeEnv(t *testing.T, rules *fakeRuleRepo, comps []application.Component, vulns []application.VulnerabilityMatch) *rebuildEnv {
	return newRebuildEnv(t, rules, comps, vulns)
}

// TestRecomputeResolvesCandidatesThroughThePreFilter: the batch of three
// pre-filtered CVEs resolves the candidate components of exactly the CVEs
// whose normalised pairs meet the inventory — v-1 and v-2 produce their
// method-led matches, v-3 (no candidate component) spawns no work and no
// error. The batch is processed in ascending id order.
func TestRecomputeResolvesCandidatesThroughThePreFilter(t *testing.T) {
	env := newRecomputeEnv(t, &fakeRuleRepo{}, []application.Component{
		rebuildReadComponent("comp-1", "acme", "widget", "1.5.0", domain.VersionSchemeSemver),
		rebuildReadComponent("comp-2", "acme", "api", "1.2.0", domain.VersionSchemeSemver),
		rebuildReadComponent("comp-3", "other", "thing", "1.0.0", domain.VersionSchemeSemver),
	}, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
		{ID: "v-2", CVEID: "CVE-2026-0002", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "api")}},
		{ID: "v-3", CVEID: "CVE-2026-0003", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "nope")}},
	})

	ctx := context.Background()
	res, err := env.run.RecomputeMatching(ctx, application.RecomputeMatchingInput{
		VulnerabilityIDs: []string{"v-1", "v-3", "v-2"}, // unsorted + includes the no-candidate CVE
		RuleVersion:      "a0000000000d0000000000",
	})
	if err != nil {
		t.Fatalf("RecomputeMatching: %v", err)
	}
	if res.Vulnerabilities != 3 || res.Candidates != 2 || res.Transactions != 1 {
		t.Fatalf("recompute result = %+v, want 3 vulnerabilities, 2 candidates in 1 transaction", res)
	}
	if n := len(env.h.db.matchRows); n != 2 {
		t.Fatalf("stored match rows = %d, want 2 (the no-candidate CVE spawns no work)", n)
	}
	if m := storedMatchPair(t, env.h, "v-1", "comp-1"); m.rec.Method != domain.MatchMethodCanonicalProductRange {
		t.Errorf("v-1×comp-1 = %s, want canonical_product_range", m.rec.Method)
	}
	if m := storedMatchPair(t, env.h, "v-2", "comp-2"); m.rec.Method != domain.MatchMethodCanonicalProductRange {
		t.Errorf("v-2×comp-2 = %s, want canonical_product_range", m.rec.Method)
	}
	for _, m := range env.h.db.matchRows {
		if m.rec.ComponentID == "comp-3" || m.rec.VulnerabilityID == "v-3" {
			t.Fatalf("no-candidate side matched unexpectedly: %+v", m.rec)
		}
	}
}

// TestRecomputeTwiceYieldsIdenticalMatches is the recompute idempotency
// acceptance: re-running the same pre-filtered batch (the same dedupe key
// — hash of the sorted ids + component_scope + rule_version) after a
// crash or a duplicate claim yields the same matches and no duplicate
// rows; shuffling the batch and repeating an id changes nothing.
func TestRecomputeTwiceYieldsIdenticalMatches(t *testing.T) {
	env := newRecomputeEnv(t, &fakeRuleRepo{}, []application.Component{
		rebuildReadComponent("comp-1", "acme", "widget", "1.5.0", domain.VersionSchemeSemver),
		rebuildReadComponent("comp-2", "acme", "api", "1.2.0", domain.VersionSchemeSemver),
	}, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
		{ID: "v-2", CVEID: "CVE-2026-0002", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "api")}},
	})
	ctx := context.Background()
	in := application.RecomputeMatchingInput{
		VulnerabilityIDs: []string{"v-1", "v-2"},
		RuleVersion:      "a0000000000d0000000000",
	}
	shuffled := application.RecomputeMatchingInput{
		VulnerabilityIDs: []string{"v-2", "v-1", "v-2"}, // reordered + duplicate id
		RuleVersion:      "a0000000000d0000000000",
	}

	first, err := env.run.RecomputeMatching(ctx, in)
	if err != nil {
		t.Fatalf("RecomputeMatching (first run): %v", err)
	}
	second, err := env.run.RecomputeMatching(ctx, shuffled)
	if err != nil {
		t.Fatalf("RecomputeMatching (re-run): %v", err)
	}
	if first != second {
		t.Fatalf("re-run result = %+v, want the first run's %+v", second, first)
	}
	if n := len(env.h.db.matchRows); n != 2 {
		t.Fatalf("stored match rows after the re-run = %d, want 2 (no duplicates)", n)
	}
	if pairRowCount(env.h, "v-1", "comp-1") != 1 || pairRowCount(env.h, "v-2", "comp-2") != 1 {
		t.Fatal("a re-run must never add a second row for an already-matched pair")
	}
}

// TestRecomputeDedupeKeyContract is the ARCH-003 §5 dedupe key of
// matching.recompute: hash(sorted id list) + component_scope +
// rule_version, namespaced by the job type. The key is independent of the
// batch order and of duplicates, changes when the id set changes, and
// never collides with the matching.rebuild namespace.
func TestRecomputeDedupeKeyContract(t *testing.T) {
	key := application.MatchingRecomputeDedupeKey([]string{"v-2", "v-1"}, "acme/widget", "a0000000000d0000000000")
	keyReordered := application.MatchingRecomputeDedupeKey([]string{"v-1", "v-2"}, "acme/widget", "a0000000000d0000000000")
	keyDuplicated := application.MatchingRecomputeDedupeKey([]string{"v-2", "v-1", "v-2"}, "acme/widget", "a0000000000d0000000000")
	if key != keyReordered || key != keyDuplicated {
		t.Fatalf("dedupe key must be order- and duplicate-independent: %q vs %q vs %q", key, keyReordered, keyDuplicated)
	}
	if !strings.HasPrefix(key, "matching.recompute:") {
		t.Fatalf("dedupe key %q must carry the matching.recompute namespace (the outbox UQ is global across job types)", key)
	}
	if len(key) != len("matching.recompute:acme/widget:a0000000000d0000000000:")+64 {
		t.Fatalf("dedupe key %q: want the scope + rule_version + a 64-hex sha-256 of the sorted ids", key)
	}
	if key == application.MatchingRecomputeDedupeKey([]string{"v-1", "v-3"}, "acme/widget", "a0000000000d0000000000") {
		t.Fatal("dedupe key must change when the id set changes")
	}
	if key == application.MatchingRecomputeDedupeKey([]string{"v-2", "v-1"}, "other", "a0000000000d0000000000") {
		t.Fatal("dedupe key must change when the component scope changes")
	}
	if key == application.MatchingRecomputeDedupeKey([]string{"v-2", "v-1"}, "acme/widget", "a0000000001d0000000000") {
		t.Fatal("dedupe key must change when the rule version changes")
	}
	if strings.HasPrefix(key, "matching.rebuild:") {
		t.Fatal("dedupe key must not collide with the matching.rebuild namespace")
	}
	rebuildKey := application.MatchingRebuildDedupeKey("a0000000000d0000000000", strings.Repeat("ab", 32))
	if rebuildKey == key {
		t.Fatal("rebuild and recompute keys must never collide")
	}
}

// TestRecomputeRejectsOversizedAndEmptyBatches: a recompute job whose
// batch exceeds the ARCH-003 §5 guide of 500 ids, an empty batch or a
// payload without a rule version is a permanent validation failure — the
// relay dead-letters it instead of retrying.
func TestRecomputeRejectsOversizedAndEmptyBatches(t *testing.T) {
	env := newRecomputeEnv(t, &fakeRuleRepo{}, nil, nil)
	ctx := context.Background()

	_, err := env.run.RecomputeMatching(ctx, application.RecomputeMatchingInput{})
	if err == nil || kindOf(t, err) != application.KindValidation {
		t.Fatalf("empty input: err = %v, want a validation error", err)
	}
	_, err = env.run.RecomputeMatching(ctx, application.RecomputeMatchingInput{
		VulnerabilityIDs: []string{"v-1"}, // no rule version
	})
	if err == nil || kindOf(t, err) != application.KindValidation {
		t.Fatalf("missing rule version: err = %v, want a validation error", err)
	}
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = fmt.Sprintf("v-%03d", i)
	}
	_, err = env.run.RecomputeMatching(ctx, application.RecomputeMatchingInput{
		VulnerabilityIDs: ids,
		RuleVersion:      "a0000000000d0000000000",
	})
	if err == nil || kindOf(t, err) != application.KindValidation {
		t.Fatalf("501-id batch: err = %v, want a validation error (batch guide 500)", err)
	}
}

// TestRecomputeMissingRowIsPermanent: a batch referencing a
// vulnerability row that does not exist (vulnerabilities are never
// deleted — an unknown id is an enqueuer bug) is a not-found error, i.e.
// a permanent job failure the relay dead-letters.
func TestRecomputeMissingRowIsPermanent(t *testing.T) {
	env := newRecomputeEnv(t, &fakeRuleRepo{}, nil, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
	})
	_, err := env.run.RecomputeMatching(context.Background(), application.RecomputeMatchingInput{
		VulnerabilityIDs: []string{"v-1", "v-missing"},
		RuleVersion:      "a0000000000d0000000000",
	})
	if err == nil || kindOf(t, err) != application.KindNotFound {
		t.Fatalf("err = %v, want a not-found error", err)
	}
}
