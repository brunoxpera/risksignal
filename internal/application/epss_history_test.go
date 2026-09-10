package application_test

// Unit tests for the WP-3.10 epss_history loader (DEV-053 acceptance:
// "history append-only + relevant-only"): the append happens for exactly the
// run's CVEs with inventory relevance — the candidate pre-filter's set
// (ARCH-003 §4/§7) — and for no other. The loader's persistence dependencies
// are the matching read ports (rule state, component walk + product index,
// reverse pair read) and the append-only history write, so the tests run
// against in-memory stubs — no database, no network.

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/matching"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// errReverseRead is the injected failure of the error-propagation test.
var errReverseRead = errors.New("reverse pair read failure")

// ruleRepoStub is the MatchingRuleRepo fake that only serves the effective
// alias rules the loader reads; the unused rule-state methods panic through
// the embedded nil interface (a test bug if ever called).
type ruleRepoStub struct {
	application.MatchingRuleRepo
	rules []domain.AliasRule
}

func (s ruleRepoStub) EffectiveAliasRules(context.Context) ([]domain.AliasRule, error) {
	return s.rules, nil
}

// componentsStub is the MatchingComponents fake: the inventory is a flat
// component list paged by id (ListComponentsPage) and indexed by the
// normalised (vendor, product) key (ListByVendorProductNorm, the semi-join
// read of CandidateComponentIDs).
type componentsStub struct {
	application.MatchingComponents
	components []application.Component
	norm       map[[2]string][]application.Component
}

func (s *componentsStub) ListComponentsPage(_ context.Context, afterID string, limit int) ([]application.Component, error) {
	out := make([]application.Component, 0, limit)
	for _, c := range s.components {
		if c.ID <= afterID {
			continue
		}
		out = append(out, c)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *componentsStub) ListByVendorProductNorm(_ context.Context, vendorNorm, productNorm string) ([]application.Component, error) {
	return s.norm[[2]string{vendorNorm, productNorm}], nil
}

// vulnRepoStub is the MatchingVulnerabilityRepo fake: ListByPairs returns a
// scripted row set (the reverse read), keyed by nothing — a test controls
// exactly which rows the loader sees, mirroring the SQL superset contract
// (rows the loader must drop again when their pairs meet no component).
type vulnRepoStub struct {
	application.MatchingVulnerabilityRepo
	rows []application.VulnerabilityMatch
	err  error
}

func (s *vulnRepoStub) ListByPairs(context.Context, []application.VendorProductPair) ([]application.VulnerabilityMatch, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.rows, nil
}

// historyStub records every appended epss_history row.
type historyStub struct {
	records []application.EpssHistoryRecord
	err     error
}

func (s *historyStub) Append(_ context.Context, _ application.Tx, rec application.EpssHistoryRecord) error {
	if s.err != nil {
		return s.err
	}
	s.records = append(s.records, rec)
	return nil
}

// numericOf parses one decimal literal into the COPY-ready numeric the
// loader carries through.
func numericOf(t *testing.T, v string) pgtype.Numeric {
	t.Helper()
	var n pgtype.Numeric
	if err := n.Scan(v); err != nil {
		t.Fatalf("parse numeric %q: %v", v, err)
	}
	return n
}

// affected names one affected-product statement carrying a name pair.
func affected(vendor, product string) matching.AffectedProduct {
	return matching.AffectedProduct{Vendor: vendor, Product: product}
}

// observation renders one run row.
func observation(t *testing.T, cve, score, percentile string) application.EpssHistoryObservation {
	t.Helper()
	return application.EpssHistoryObservation{CVEID: cve, Score: numericOf(t, score), Percentile: numericOf(t, percentile)}
}

// newHistoryLoader assembles the loader over the given stubs.
func newHistoryLoader(t *testing.T, rules application.MatchingRuleRepo, comps application.MatchingComponents, vulns application.MatchingVulnerabilityRepo, hist application.EpssHistoryRepo) *application.EpssHistoryLoader {
	t.Helper()
	l, err := application.NewEpssHistoryLoader(rules, comps, vulns, hist)
	if err != nil {
		t.Fatalf("NewEpssHistoryLoader: %v", err)
	}
	return l
}

var epssObservedOn = time.Date(2026, 9, 9, 9, 30, 0, 0, time.UTC)

// TestEpssHistoryLoaderAppendsOnlyRelevantCVEs is the core relevant-only
// contract: the run's daily set carries a relevant CVE (its affected pair
// meets a component through the product index), an alias-relevant CVE (whose
// raw pair is an alias variant of the component's key) and an irrelevant CVE
// (whose affected pair meets no component) — only the first two append
// history, stamped with the run date and the file's model version.
func TestEpssHistoryLoaderAppendsOnlyRelevantCVEs(t *testing.T) {
	rules := ruleRepoStub{rules: []domain.AliasRule{
		mustAliasRule(t, "vendor-alias", domain.AliasScopeVendor, "acme", "acme-corp"),
	}}
	comps := &componentsStub{
		components: []application.Component{
			{ID: "comp-1", VendorNorm: "acme", ProductNorm: "portal"},
		},
		norm: map[[2]string][]application.Component{
			{"acme", "portal"}: {{ID: "comp-1"}},
		},
	}
	vulns := &vulnRepoStub{rows: []application.VulnerabilityMatch{
		{ID: "vuln-rel", CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{affected("acme", "portal")}},
		{ID: "vuln-alias", CVEID: "CVE-2026-0002", Statements: []matching.AffectedProduct{affected("acme-corp", "portal")}},
		{ID: "vuln-irr", CVEID: "CVE-2026-0003", Statements: []matching.AffectedProduct{affected("other", "thing")}},
	}}
	hist := &historyStub{}
	loader := newHistoryLoader(t, rules, comps, vulns, hist)

	observed := []application.EpssHistoryObservation{
		observation(t, "CVE-2026-0001", "0.97368", "0.9991"),
		observation(t, "CVE-2026-0002", "0.50000", "0.8000"),
		observation(t, "CVE-2026-0003", "0.00510", "0.4021"),
		observation(t, "CVE-2026-9999", "0.10000", "0.2000"), // absent from the reverse read — never relevant
	}

	n, err := loader.AppendRelevant(context.Background(), nil, observed, epssObservedOn, "2026-09-08")
	if err != nil {
		t.Fatalf("AppendRelevant: %v", err)
	}
	if n != 2 || len(hist.records) != 2 {
		t.Fatalf("appended = %d (%d rows), want 2 — only the relevant CVEs", n, len(hist.records))
	}
	// Ascending CVE order (deterministic), each stamped with the run date
	// and the file's model version.
	if got := []string{hist.records[0].CVEID, hist.records[1].CVEID}; !reflect.DeepEqual(got, []string{"CVE-2026-0001", "CVE-2026-0002"}) {
		t.Fatalf("appended CVEs = %v, want the relevant pair in ascending order", got)
	}
	for _, rec := range hist.records {
		if !rec.ObservedOn.Equal(epssObservedOn) {
			t.Fatalf("%s observed_on = %v, want the run date %v", rec.CVEID, rec.ObservedOn, epssObservedOn)
		}
		if rec.ModelVersion != "2026-09-08" {
			t.Fatalf("%s model_version = %q, want the file date (independent of the run date)", rec.CVEID, rec.ModelVersion)
		}
	}
	// The score/percentile travel verbatim from the run's row.
	score, err := hist.records[0].Score.Float64Value()
	if err != nil || !score.Valid || score.Float64 != 0.97368 {
		t.Fatalf("appended score = %v, %v; want the run's 0.97368", score, err)
	}
}

// TestEpssHistoryLoaderWithoutInventoryAppendsNothing proves the
// no-candidate ⇒ no-work gate of ADR-012: an empty inventory resolves no
// relevant CVE, so the loader appends nothing and never reads the reverse
// pair index.
func TestEpssHistoryLoaderWithoutInventoryAppendsNothing(t *testing.T) {
	comps := &componentsStub{}
	vulns := &vulnRepoStub{err: errors.New("must not be called")}
	hist := &historyStub{}
	loader := newHistoryLoader(t, ruleRepoStub{}, comps, vulns, hist)

	n, err := loader.AppendRelevant(context.Background(), nil,
		[]application.EpssHistoryObservation{observation(t, "CVE-2026-0001", "0.5", "0.5")}, epssObservedOn, "2026-09-09")
	if err != nil || n != 0 || len(hist.records) != 0 {
		t.Fatalf("empty inventory: appended %d (%d rows), err %v; want 0 and no reverse read", n, len(hist.records), err)
	}
}

// TestEpssHistoryLoaderEmptyRunAppendsNothing proves a run without rows (an
// empty daily file) appends nothing.
func TestEpssHistoryLoaderEmptyRunAppendsNothing(t *testing.T) {
	hist := &historyStub{}
	loader := newHistoryLoader(t, ruleRepoStub{}, &componentsStub{}, &vulnRepoStub{}, hist)
	n, err := loader.AppendRelevant(context.Background(), nil, nil, epssObservedOn, "2026-09-09")
	if err != nil || n != 0 || len(hist.records) != 0 {
		t.Fatalf("empty run: appended %d (%d rows), err %v; want 0", n, len(hist.records), err)
	}
}

// TestEpssHistoryLoaderReverseReadFailureAborts proves a failing reverse
// pair read aborts the append as an infrastructure error — history of a
// half-resolved run would silently miss relevant CVEs.
func TestEpssHistoryLoaderReverseReadFailureAborts(t *testing.T) {
	comps := &componentsStub{
		components: []application.Component{{ID: "comp-1", VendorNorm: "acme", ProductNorm: "portal"}},
	}
	vulns := &vulnRepoStub{err: errReverseRead}
	loader := newHistoryLoader(t, ruleRepoStub{}, comps, vulns, &historyStub{})

	_, err := loader.AppendRelevant(context.Background(), nil,
		[]application.EpssHistoryObservation{observation(t, "CVE-2026-0001", "0.5", "0.5")}, epssObservedOn, "2026-09-09")
	if !errors.Is(err, errReverseRead) {
		t.Fatalf("err = %v, want the reverse read failure to propagate", err)
	}
	if kind, ok := application.ErrorKindOf(err); !ok || kind != application.KindInfra {
		t.Fatalf("error kind = %q (ok=%v), want %q", kind, ok, application.KindInfra)
	}
}

// TestEpssHistoryLoaderChainedRulesetRejected proves the loader validates
// the alias ruleset before resolving anything (chained rules are a data
// error, ARCH-003 §2) — the append fails fast instead of poisoning every
// closure.
func TestEpssHistoryLoaderChainedRulesetRejected(t *testing.T) {
	rules := ruleRepoStub{rules: []domain.AliasRule{
		mustAliasRule(t, "vendor-a", domain.AliasScopeVendor, "a", "b"),
		mustAliasRule(t, "vendor-b", domain.AliasScopeVendor, "b", "c"),
	}}
	loader := newHistoryLoader(t, rules,
		&componentsStub{components: []application.Component{{ID: "comp-1", VendorNorm: "a", ProductNorm: "p"}}},
		&vulnRepoStub{}, &historyStub{})

	_, err := loader.AppendRelevant(context.Background(), nil,
		[]application.EpssHistoryObservation{observation(t, "CVE-2026-0001", "0.5", "0.5")}, epssObservedOn, "2026-09-09")
	if kind, ok := application.ErrorKindOf(err); !ok || kind != application.KindValidation {
		t.Fatalf("chained ruleset error = %v (kind %q), want validation", err, kind)
	}
}
