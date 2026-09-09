package application_test

// Unit tests of the WP-3.08 matching.rebuild run (DEV-064, ARCH-003 §5,
// ADR-012): the inventory-driven walk the inventory commit of DEV-060
// enqueues — components walked in bounded pages, the candidate CVEs of a
// page's normalised name pairs resolved through the reverse pre-filter
// read (never per CVE — the work is bounded by the component set),
// assembled into MatchCandidates (application.Component → domain.Component
// conversion) and committed through the DEV-063 RunMatching core in
// bounded transactions. The tests drive the DEV-064 acceptance criteria
// on the fake persistence:
//
//   - rebuild walks and matches: every component of the inventory is
//     evaluated against exactly its candidate CVEs; a provably-not-
//     affected pair is stored as a visible no_match and a decision-rule
//     exclusion survives the rebuild;
//   - rebuild twice (same job payload) → identical matches, zero
//     duplicates (UQ (vulnerability_id, component_id, rule_version));
//   - the matching.rebuild row DEV-060's commit enqueues is consumed
//     end-to-end: payload decode + run → matches of the committed
//     inventory;
//   - a crash mid-run (page 2 fails after page 1 committed) leaves the
//     committed page in place and the re-run (re-claimed job) resumes
//     with no double effect.
//
// The runs are fake-driven at the ports (rules, components, vulnerability
// statements — the real adapters arrive with the WP-3.09 statement
// store); the RunMatching core is the real application service over the
// shared fake persistence of fakes_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/application/matching"
	"github.com/xpera/risksignal/internal/application/normalise"
	"github.com/xpera/risksignal/internal/domain"
)

// ---------------------------------------------------------------------------
// fake matching reads (rules, components, vulnerability statements)

// fakeRuleRepo is the MatchingRuleRepo fake of the matching-run tests: a
// fixed rule state the test pins (rules + the two version counters).
type fakeRuleRepo struct {
	aliasRules      []domain.AliasRule
	decisionRules   []domain.DecisionRule
	aliasVersion    int
	decisionVersion int
}

func (f *fakeRuleRepo) EffectiveAliasRules(context.Context) ([]domain.AliasRule, error) {
	return append([]domain.AliasRule(nil), f.aliasRules...), nil
}
func (f *fakeRuleRepo) EffectiveDecisionRules(context.Context) ([]domain.DecisionRule, error) {
	return append([]domain.DecisionRule(nil), f.decisionRules...), nil
}
func (f *fakeRuleRepo) AliasVersion(context.Context) (int, error) { return f.aliasVersion, nil }
func (f *fakeRuleRepo) DecisionVersion(context.Context) (int, error) {
	return f.decisionVersion, nil
}

var _ application.MatchingRuleRepo = (*fakeRuleRepo)(nil)

// fakeMatchingComponents is the MatchingComponents fake: a fixed store of
// full I3 read-model rows served in ascending id order (the keyset page
// walk), by id (the candidate row read) and by normalised pair (the
// inventory product index lookup of the pre-filter). The failure
// failpoints arm the crash tests.
type fakeMatchingComponents struct {
	rows []application.Component // ascending by ID

	pageErr error // injected ListComponentsPage failure
	idsErr  error // injected ListComponentsByIDs failure
	normErr error // injected ListByVendorProductNorm failure
}

func (f *fakeMatchingComponents) ListComponentsPage(_ context.Context, afterID string, limit int) ([]application.Component, error) {
	if f.pageErr != nil {
		return nil, f.pageErr
	}
	start := 0
	if afterID != "" {
		for start < len(f.rows) && f.rows[start].ID <= afterID {
			start++
		}
	}
	end := start + limit
	if end > len(f.rows) {
		end = len(f.rows)
	}
	return append([]application.Component(nil), f.rows[start:end]...), nil
}

func (f *fakeMatchingComponents) ListComponentsByIDs(_ context.Context, ids []string) ([]application.Component, error) {
	if f.idsErr != nil {
		return nil, f.idsErr
	}
	byID := make(map[string]application.Component, len(f.rows))
	for _, r := range f.rows {
		byID[r.ID] = r
	}
	out := make([]application.Component, 0, len(ids))
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			return nil, application.NotFoundError("matching_components.by_ids", fmt.Errorf("component %s not found", id))
		}
		out = append(out, c)
	}
	return out, nil
}

func (f *fakeMatchingComponents) ListByVendorProductNorm(_ context.Context, vendorNorm, productNorm string) ([]application.Component, error) {
	if f.normErr != nil {
		return nil, f.normErr
	}
	var out []application.Component
	for _, c := range f.rows {
		if c.VendorNorm == vendorNorm && c.ProductNorm == productNorm {
			out = append(out, c)
		}
	}
	return out, nil
}

var _ application.MatchingComponents = (*fakeMatchingComponents)(nil)

// fakeMatchingVulns is the MatchingVulnerabilityRepo fake: a fixed store
// of statement-bearing vulnerability rows served ascending by id.
// ListByPairs matches the raw affected-name pairs of a row against the
// given query pairs (the reverse pre-filter read); the pairsFailAfter
// failpoint arms the crash test (the Nth ListByPairs call fails after the
// earlier pages already committed).
type fakeMatchingVulns struct {
	rows []application.VulnerabilityMatch // ascending by ID

	pairsErr       error
	idsErr         error
	pairsFailAfter int // fail the call once this many ListByPairs calls succeeded (-1: never)
	pairsCalls     int
}

func (f *fakeMatchingVulns) ListByIDs(_ context.Context, ids []string) ([]application.VulnerabilityMatch, error) {
	if f.idsErr != nil {
		return nil, f.idsErr
	}
	byID := make(map[string]application.VulnerabilityMatch, len(f.rows))
	for _, r := range f.rows {
		byID[r.ID] = r
	}
	out := make([]application.VulnerabilityMatch, 0, len(ids))
	for _, id := range ids {
		row, ok := byID[id]
		if !ok {
			return nil, application.NotFoundError("matching_vulns.by_ids", fmt.Errorf("vulnerability %s not found", id))
		}
		out = append(out, row)
	}
	return out, nil
}

func (f *fakeMatchingVulns) ListByPairs(_ context.Context, pairs []application.VendorProductPair) ([]application.VulnerabilityMatch, error) {
	if f.pairsErr != nil {
		return nil, f.pairsErr
	}
	if f.pairsFailAfter >= 0 {
		if f.pairsCalls >= f.pairsFailAfter {
			return nil, errors.New("injected: vulnerability pair read failure")
		}
		f.pairsCalls++
	}
	var out []application.VulnerabilityMatch
	for _, row := range f.rows {
		if rowHasPair(row, pairs) {
			out = append(out, row)
		}
	}
	return out, nil
}

var _ application.MatchingVulnerabilityRepo = (*fakeMatchingVulns)(nil)

// rowHasPair reports whether one raw affected-name pair of the row is a
// member of the query pair set.
func rowHasPair(row application.VulnerabilityMatch, pairs []application.VendorProductPair) bool {
	for _, q := range pairs {
		for i := range row.Statements {
			s := &row.Statements[i]
			if s.Vendor != "" && s.Product != "" &&
				normalise.NormaliseKey(s.Vendor) == q.Vendor && normalise.NormaliseKey(s.Product) == q.Product {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// fixtures

// rebuildReadComponent is one persisted read-model component row of the
// fixture inventory: the raw originals verbatim plus the write-time
// normalised comparison keys and the inferred scheme, exactly as the I3
// rows are stored. vendor/product are the raw originals; the norm keys
// are the folded forms the fixture uses as both (lowercase — already
// folded). VersionScheme is pinned by the caller (semver for the
// window-evaluation fixtures).
func rebuildReadComponent(id, vendor, product, version string, scheme domain.VersionScheme) application.Component {
	ids := domain.ComponentIdentifiers{Vendor: vendor, Product: product, Version: version}
	normVendor, normProduct := normalise.NormaliseKey(vendor), normalise.NormaliseKey(product)
	dc, err := domain.NewComponent(id, "asset-"+id, ids, normVendor, normProduct, "", scheme)
	if err != nil {
		panic("rebuildReadComponent: " + err.Error())
	}
	return application.Component{
		ID:            id,
		AssetID:       dc.AssetID,
		Vendor:        vendor,
		Product:       product,
		Version:       version,
		VendorNorm:    normVendor,
		ProductNorm:   normProduct,
		VersionScheme: scheme,
		NaturalKey:    dc.NaturalKey,
	}
}

// rebuildWindowStatement is one affected-product statement naming the
// pair with an affected window [1.0, 2.0) — the fixture of the
// window-evaluation cases (a component version inside the window is
// affected, outside is provably not).
func rebuildWindowStatement(vendor, product string) matching.AffectedProduct {
	return matching.AffectedProduct{
		Vendor:  vendor,
		Product: product,
		Ranges:  []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}},
	}
}

// rebuildUnboundedStatement names the pair without any affected-version
// expression — the fixture of the uncertain cases (canonical pair without
// a version relation never rises above product_uncertain_version).
func rebuildUnboundedStatement(vendor, product string) matching.AffectedProduct {
	return matching.AffectedProduct{Vendor: vendor, Product: product}
}

// rebuildEnv wires the matching-run fakes plus the real application
// service (the RunMatching core over the shared fake persistence).
type rebuildEnv struct {
	h     *harness
	rules *fakeRuleRepo
	comps *fakeMatchingComponents
	vulns *fakeMatchingVulns
	run   *application.MatchingRunner
}

func newRebuildEnv(t *testing.T, rules *fakeRuleRepo, comps []application.Component, vulns []application.VulnerabilityMatch) *rebuildEnv {
	t.Helper()
	h := newHarness(t)
	env := &rebuildEnv{
		h:     h,
		rules: rules,
		comps: &fakeMatchingComponents{rows: comps},
		vulns: &fakeMatchingVulns{rows: vulns, pairsFailAfter: -1},
	}
	runner, err := application.NewMatchingRunner(h.svc, env.rules, env.comps, env.vulns, h.clock, nil)
	if err != nil {
		t.Fatalf("NewMatchingRunner: %v", err)
	}
	env.run = runner
	return env
}

// storedMatchPair returns the stored match row of one (vulnerability,
// component) pair.
func storedMatchPair(t *testing.T, h *harness, vulnID, compID string) storedMatch {
	t.Helper()
	for _, m := range h.db.matchRows {
		if m.rec.VulnerabilityID == vulnID && m.rec.ComponentID == compID {
			return m
		}
	}
	t.Fatalf("no stored match for (%s, %s)", vulnID, compID)
	return storedMatch{}
}

// pairRows counts the stored match rows of one (vulnerability, component)
// pair across rule versions — the duplicate detector of the re-run tests.
func pairRowCount(h *harness, vulnID, compID string) int {
	n := 0
	for _, m := range h.db.matchRows {
		if m.rec.VulnerabilityID == vulnID && m.rec.ComponentID == compID {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// tests

// TestRebuildWalksComponentsAndMatchesCandidates is the inventory-driven
// walk of ARCH-003 §5: every component of the inventory is evaluated
// against exactly its candidate CVEs — resolved per page through the
// reverse pre-filter over the components' normalised name pairs, never
// per CVE — and the outcomes are stored as method-led matches. The
// fixture: comp-1 (acme/widget 1.5.0) is affected by v1's window and
// only uncertainly related to v3's window-less statement; comp-2
// (acme/api 1.2.0) matches v2; comp-3 (other/thing) has no candidate CVE
// and spawns no work; comp-4 (acme/widget 3.0.0) is provably outside v1's
// window and stores a visible no_match.
func TestRebuildWalksComponentsAndMatchesCandidates(t *testing.T) {
	env := newRebuildEnv(t, &fakeRuleRepo{}, []application.Component{
		rebuildReadComponent("comp-1", "acme", "widget", "1.5.0", domain.VersionSchemeSemver),
		rebuildReadComponent("comp-2", "acme", "api", "1.2.0", domain.VersionSchemeSemver),
		rebuildReadComponent("comp-3", "other", "thing", "1.0.0", domain.VersionSchemeSemver),
		rebuildReadComponent("comp-4", "acme", "widget", "3.0.0", domain.VersionSchemeSemver),
	}, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
		{ID: "v-2", CVEID: "CVE-2026-0002", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "api")}},
		{ID: "v-3", CVEID: "CVE-2026-0003", Statements: []matching.AffectedProduct{rebuildUnboundedStatement("acme", "widget")}},
	})

	ctx := context.Background()
	res, err := env.run.RebuildMatching(ctx, application.RebuildMatchingInput{
		RuleVersion:       "a0000000000d0000000000",
		InventorySnapshot: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatalf("RebuildMatching: %v", err)
	}
	if res.Components != 4 || res.Candidates != 5 || res.Transactions != 1 {
		t.Fatalf("rebuild result = %+v, want 4 components, 5 candidates in 1 transaction", res)
	}
	if n := len(env.h.db.matchRows); n != 5 {
		t.Fatalf("stored match rows = %d, want 5", n)
	}

	ruleVersion := "a0000000000d0000000000"
	// v1 × comp-1: inside the window → canonical_product_range/high/80.
	affected := storedMatchPair(t, env.h, "v-1", "comp-1")
	if affected.rec.Method != domain.MatchMethodCanonicalProductRange ||
		affected.rec.Confidence != domain.ConfidenceHigh || affected.rec.Score != 80 {
		t.Errorf("v1×comp-1 = %s/%s/%d, want canonical_product_range/high/80",
			affected.rec.Method, affected.rec.Confidence, affected.rec.Score)
	}
	if affected.rec.RuleVersion != ruleVersion {
		t.Errorf("v1×comp-1 rule_version = %q, want %q", affected.rec.RuleVersion, ruleVersion)
	}
	// v1 × comp-4: provably outside the window → stored no_match.
	outside := storedMatchPair(t, env.h, "v-1", "comp-4")
	if outside.rec.Method != domain.MatchMethodNoMatch ||
		outside.rec.Confidence != domain.ConfidenceNone || outside.rec.Score != 0 {
		t.Errorf("v1×comp-4 = %s/%s/%d, want the stored no_match of the provable negative",
			outside.rec.Method, outside.rec.Confidence, outside.rec.Score)
	}
	// v3 × comp-1/comp-4: window-less canonical pair → uncertain.
	for _, comp := range []string{"comp-1", "comp-4"} {
		m := storedMatchPair(t, env.h, "v-3", comp)
		if m.rec.Method != domain.MatchMethodProductUncertainVersion ||
			m.rec.Confidence != domain.ConfidenceMedium || m.rec.Score != 65 {
			t.Errorf("v3×%s = %s/%s/%d, want product_uncertain_version/medium/65",
				comp, m.rec.Method, m.rec.Confidence, m.rec.Score)
		}
	}
	// v2 × comp-2: affected → canonical_product_range.
	if m := storedMatchPair(t, env.h, "v-2", "comp-2"); m.rec.Method != domain.MatchMethodCanonicalProductRange {
		t.Errorf("v2×comp-2 = %s, want canonical_product_range", m.rec.Method)
	}
	// comp-3 has no candidate CVE: no row references it.
	for _, m := range env.h.db.matchRows {
		if m.rec.ComponentID == "comp-3" {
			t.Fatalf("component comp-3 matched unexpectedly: %+v", m.rec)
		}
	}
}

// TestRebuildTwiceYieldsIdenticalMatches is the DEV-064 idempotency
// acceptance test: running the same matching.rebuild job twice (same
// rule_version + inventory_snapshot dedupe key, re-run after a crash or a
// duplicate claim) yields the same matches and no duplicate rows — the UQ
// (vulnerability_id, component_id, rule_version) insert of the core
// absorbs the overlap (TR-012).
func TestRebuildTwiceYieldsIdenticalMatches(t *testing.T) {
	env := newRebuildEnv(t, &fakeRuleRepo{}, []application.Component{
		rebuildReadComponent("comp-1", "acme", "widget", "1.5.0", domain.VersionSchemeSemver),
	}, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
		{ID: "v-2", CVEID: "CVE-2026-0002", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
	})
	ctx := context.Background()
	in := application.RebuildMatchingInput{
		RuleVersion:       "a0000000000d0000000000",
		InventorySnapshot: strings.Repeat("ab", 32),
	}

	first, err := env.run.RebuildMatching(ctx, in)
	if err != nil {
		t.Fatalf("RebuildMatching (first run): %v", err)
	}
	second, err := env.run.RebuildMatching(ctx, in)
	if err != nil {
		t.Fatalf("RebuildMatching (re-run): %v", err)
	}
	if first != second {
		t.Fatalf("re-run result = %+v, want the first run's %+v", second, first)
	}
	if n := len(env.h.db.matchRows); n != 2 {
		t.Fatalf("stored match rows after the re-run = %d, want 2 (no duplicates)", n)
	}
	if pairRowCount(env.h, "v-1", "comp-1") != 1 || pairRowCount(env.h, "v-2", "comp-1") != 1 {
		t.Fatal("a re-run must never add a second row for an already-matched pair")
	}
	// The re-run resolved the same canonical rows (same ids, same records,
	// same injected-clock created_at — nothing was written again).
	for _, m := range env.h.db.matchRows {
		if !m.createdAt.Equal(fixedNow) {
			t.Errorf("match %s/%s created_at = %v, want the injected clock %v",
				m.rec.VulnerabilityID, m.rec.ComponentID, m.createdAt, fixedNow)
		}
	}
}

// TestRebuildResolvesCandidatesThroughTheAliasClosure: the reverse
// pre-filter expands the component's name pair through the symmetric
// one-hop alias closure before the pair read, so a CVE whose raw pair
// carries the alias variant meets the canonical-keyed component — the
// engine then records the alias-only evidence (controlled_alias_only for
// the window-less statement). Both sides are closed before the
// semi-join, so a canonical name and its aliases meet symmetrically
// (ARCH-003 §2 item 2).
func TestRebuildResolvesCandidatesThroughTheAliasClosure(t *testing.T) {
	aliasRule, err := domain.NewAliasRule("ar-1", domain.AliasScopeVendor, "sun", "oracle", "sun is oracle", 3)
	if err != nil {
		t.Fatalf("NewAliasRule: %v", err)
	}
	env := newRebuildEnv(t, &fakeRuleRepo{
		aliasRules:   []domain.AliasRule{aliasRule},
		aliasVersion: 3,
	}, []application.Component{
		rebuildReadComponent("comp-1", "oracle", "java", "8u1", domain.VersionSchemeSemver),
	}, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildUnboundedStatement("sun", "java")}},
	})

	res, err := env.run.RebuildMatching(context.Background(), application.RebuildMatchingInput{
		RuleVersion:       "a0000000003d0000000000",
		InventorySnapshot: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatalf("RebuildMatching: %v", err)
	}
	if res.Candidates != 1 {
		t.Fatalf("rebuild result = %+v, want exactly the alias pair as 1 candidate", res)
	}
	m := storedMatchPair(t, env.h, "v-1", "comp-1")
	if m.rec.Method != domain.MatchMethodControlledAliasOnly ||
		m.rec.Confidence != domain.ConfidenceMedium || m.rec.Score != 55 {
		t.Errorf("alias pair = %s/%s/%d, want controlled_alias_only/medium/55",
			m.rec.Method, m.rec.Confidence, m.rec.Score)
	}
	if m.rec.RuleVersion != "a0000000003d0000000000" {
		t.Errorf("alias pair rule_version = %q, want the ruleset of the alias rule", m.rec.RuleVersion)
	}
}

// TestRebuildAppliesDecisionRules is the ARCH-003 §3 survival criterion
// over matching.rebuild: an exclude rule of the current ruleset turns the
// raw computed match of its target into a visible no_match referencing
// the rule — the recompute never silently re-adds the automatic match
// because the no_match row occupies the pair's UQ key.
func TestRebuildAppliesDecisionRules(t *testing.T) {
	exclude, err := domain.NewDecisionRule("dr-1", domain.DecisionRuleTypeExclude,
		domain.DecisionTarget{CVEID: "CVE-2026-0001", Product: "widget"}, nil,
		"manual correction: unit fixture", "alice", 2, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("NewDecisionRule: %v", err)
	}
	env := newRebuildEnv(t, &fakeRuleRepo{
		decisionRules:   []domain.DecisionRule{exclude},
		decisionVersion: 2,
	}, []application.Component{
		rebuildReadComponent("comp-1", "acme", "widget", "1.5.0", domain.VersionSchemeSemver),
	}, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
	})

	if _, err := env.run.RebuildMatching(context.Background(), application.RebuildMatchingInput{
		RuleVersion:       "a0000000000d0000000002",
		InventorySnapshot: strings.Repeat("ab", 32),
	}); err != nil {
		t.Fatalf("RebuildMatching: %v", err)
	}
	m := storedMatchPair(t, env.h, "v-1", "comp-1")
	if m.rec.Method != domain.MatchMethodNoMatch ||
		m.rec.Confidence != domain.ConfidenceNone || m.rec.Score != 0 {
		t.Errorf("excluded pair = %s/%s/%d, want the rule-forced no_match/none/0",
			m.rec.Method, m.rec.Confidence, m.rec.Score)
	}
	if m.rec.DecisionRuleID == nil || *m.rec.DecisionRuleID != "dr-1" {
		t.Errorf("excluded pair decision_rule_id = %v, want dr-1", m.rec.DecisionRuleID)
	}
	if m.rec.RuleVersion != "a0000000000d0000000002" {
		t.Errorf("excluded pair rule_version = %q, want the ruleset of the decision rule", m.rec.RuleVersion)
	}
}

// TestRebuildConsumesTheCommitEnqueuedJob is the DEV-064 end-to-end
// acceptance: the matching.rebuild row the DEV-060 inventory commit
// enqueued (dedupe key matching.rebuild:<rule_version>:<inventory
// snapshot>, payload {event_id, type, import_id, rule_version,
// inventory_snapshot, occurred_at, correlation_id}) is consumed — the
// payload decodes into the shared job contract and the run computes the
// matches of the committed inventory. The fake seam: the commit writes
// into the fake inventory state, while the component read port of the run
// is fed the equivalent full read-model row (the real component paging
// adapter reads the components table the commit writes — the WP-3.09
// adapter wiring).
func TestRebuildConsumesTheCommitEnqueuedJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The DEV-060 commit: one component Acme/Portal 1.0.0 of one asset —
	// enqueues exactly one matching.rebuild row.
	csv := commitCSV(commitAssetRow("cmdb", "a1", "portal-host", "Acme", "Portal", "1.0.0"))
	commitRes, err := h.svc.CommitInventory(ctx, application.CommitInventoryInput{File: []byte(csv)})
	if err != nil {
		t.Fatalf("CommitInventory: %v", err)
	}
	if !commitRes.Changed || len(h.db.outboxEvents) != 1 {
		t.Fatalf("commit result = %+v (outbox rows %d), want one changed commit with one rebuild job",
			commitRes, len(h.db.outboxEvents))
	}
	job := h.db.outboxEvents[0]
	if job.Type != application.EventTypeMatchingRebuild {
		t.Fatalf("outbox type = %q, want matching.rebuild", job.Type)
	}

	// The run reads the committed component through its component port —
	// the same natural key and comparison keys the commit wrote.
	ids := domain.ComponentIdentifiers{Vendor: "Acme", Product: "Portal", Version: "1.0.0"}
	normVendor, normProduct := normalise.NormaliseKey("Acme"), normalise.NormaliseKey("Portal")
	env := newRebuildEnv(t, &fakeRuleRepo{}, []application.Component{
		rebuildReadComponent("comp-1", "Acme", "Portal", "1.0.0", normalise.InferVersionScheme(ids, domain.VersionSchemeUnknown)),
	}, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement(normVendor, normProduct)}},
	})

	// Consume: decode the enqueued payload and run the job it describes.
	var payload application.MatchingRebuildPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		t.Fatalf("decode enqueued matching.rebuild payload: %v", err)
	}
	if payload.Type != application.EventTypeMatchingRebuild || payload.EventID == "" {
		t.Fatalf("payload envelope = %+v, want type matching.rebuild with an event id", payload)
	}
	if payload.RuleVersion != commitRes.RuleVersion || payload.InventorySnapshot != commitRes.InventorySnapshot {
		t.Fatalf("payload rule_version/snapshot = %q/%q, want the commit's %q/%q",
			payload.RuleVersion, payload.InventorySnapshot, commitRes.RuleVersion, commitRes.InventorySnapshot)
	}
	if payload.ImportID != commitRes.ImportID || payload.CorrelationID != commitRes.CorrelationID {
		t.Fatalf("payload import/correlation = %q/%q, want %q/%q",
			payload.ImportID, payload.CorrelationID, commitRes.ImportID, commitRes.CorrelationID)
	}
	if want := "matching.rebuild:" + payload.RuleVersion + ":" + payload.InventorySnapshot; job.DedupeKey != want {
		t.Fatalf("enqueued dedupe key = %q, want %q (rule_version + inventory_snapshot)", job.DedupeKey, want)
	}

	res, err := env.run.RebuildMatching(ctx, application.RebuildMatchingInput{
		RuleVersion:       payload.RuleVersion,
		InventorySnapshot: payload.InventorySnapshot,
	})
	if err != nil {
		t.Fatalf("RebuildMatching: %v", err)
	}
	if res.Components != 1 || res.Candidates != 1 {
		t.Fatalf("rebuild result = %+v, want the committed component × its candidate CVE", res)
	}
	m := storedMatchPair(t, env.h, "v-1", "comp-1")
	if m.rec.Method == domain.MatchMethodNoMatch {
		t.Fatalf("the committed component matched no_match, want a positive method-led match")
	}
	if m.rec.VulnerabilityID != "v-1" || m.rec.ComponentID != "comp-1" {
		t.Fatalf("stored match pair = %s/%s, want v-1/comp-1", m.rec.VulnerabilityID, m.rec.ComponentID)
	}
}

// TestRebuildCrashResumesWithoutDoubleEffect is the TR-012 crash/lease
// acceptance at the run level: page 1 of a two-page inventory commits;
// the run then fails on page 2 (the injected pair-read failure — the
// lease-expired job will be re-claimed and re-run). The re-run starts at
// page 1 again: the already-committed page is absorbed by the idempotent
// match insert (no double effect) and the run completes.
func TestRebuildCrashResumesWithoutDoubleEffect(t *testing.T) {
	comps := make([]application.Component, 0, 700)
	for i := 1; i <= 700; i++ {
		comps = append(comps, rebuildReadComponent(fmt.Sprintf("comp-%03d", i), "acme", "widget", "1.5.0", domain.VersionSchemeSemver))
	}
	env := newRebuildEnv(t, &fakeRuleRepo{}, comps, []application.VulnerabilityMatch{
		{ID: "v-1", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{rebuildWindowStatement("acme", "widget")}},
	})
	env.vulns.pairsFailAfter = 1 // page 2's candidate read fails
	ctx := context.Background()
	in := application.RebuildMatchingInput{
		RuleVersion:       "a0000000000d0000000000",
		InventorySnapshot: strings.Repeat("ab", 32),
	}

	// Run 1: page 1 (500 components) committed, page 2 fails.
	_, err := env.run.RebuildMatching(ctx, in)
	if err == nil {
		t.Fatal("rebuild with the injected page-2 failure succeeded, want an error")
	}
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("error kind = %s, want infrastructure (a re-claimable failure)", kind)
	}
	if n := len(env.h.db.matchRows); n != 500 {
		t.Fatalf("committed matches after the crash = %d, want the 500 of page 1", n)
	}

	// Run 2 (the re-claimed job after the lease expired): page 1 re-runs
	// as a no-op at the data level, page 2 commits — 700 rows in total.
	env.vulns.pairsFailAfter = -1 // the store recovered
	second, err := env.run.RebuildMatching(ctx, in)
	if err != nil {
		t.Fatalf("RebuildMatching (re-run): %v", err)
	}
	if second.Components != 700 || second.Candidates != 700 {
		t.Fatalf("re-run result = %+v, want all 700 components and 700 candidates", second)
	}
	if n := len(env.h.db.matchRows); n != 700 {
		t.Fatalf("stored matches after the re-run = %d, want 700 (no double effect on page 1)", n)
	}
	for _, comp := range []string{"comp-001", "comp-500", "comp-700"} {
		if pairRowCount(env.h, "v-1", comp) != 1 {
			t.Fatalf("pair (v-1, %s) stored %d rows, want exactly 1", comp, pairRowCount(env.h, "v-1", comp))
		}
	}
}

// TestRebuildValidatesTheJobContract: a job payload missing the rule
// version or the inventory snapshot (the two halves of the dedupe key) is
// a permanent validation failure — the relay dead-letters it instead of
// retrying a payload that can never succeed.
func TestRebuildValidatesTheJobContract(t *testing.T) {
	env := newRebuildEnv(t, &fakeRuleRepo{}, nil, nil)
	ctx := context.Background()

	_, err := env.run.RebuildMatching(ctx, application.RebuildMatchingInput{RuleVersion: "a0000000000d0000000000"})
	if err == nil || kindOf(t, err) != application.KindValidation {
		t.Fatalf("rebuild without a snapshot: err = %v, want a validation error", err)
	}
	_, err = env.run.RebuildMatching(ctx, application.RebuildMatchingInput{InventorySnapshot: strings.Repeat("ab", 32)})
	if err == nil || kindOf(t, err) != application.KindValidation {
		t.Fatalf("rebuild without a rule version: err = %v, want a validation error", err)
	}
}

// kindOf returns the application error kind of err.
func kindOf(t *testing.T, err error) application.ErrorKind {
	t.Helper()
	kind, ok := application.ErrorKindOf(err)
	if !ok {
		t.Fatalf("ErrorKindOf(%v) = none", err)
	}
	return kind
}
