package application_test

// Unit tests for the WP-3.07 candidate pre-filter (DEV-062 acceptance:
// "alias-closure semi-join returns only relevant components; no-candidate
// CVE → empty; dedupe/determinism"). The pre-filter's only persistence
// dependency is the ComponentNormLister port, so the tests run against an
// in-memory stub — no database, no network.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// errNormLister is the injected failure of the error-propagation test.
var errNormLister = errors.New("norm lister failure")

// normListerStub is the ComponentNormLister fake of the pre-filter tests:
// components are seeded per normalised (vendor, product) key and every
// call is recorded as "vendor/product", so a test can assert both the
// semi-join result and that a candidate-less vulnerability causes no
// index read at all (ADR-012: no candidate ⇒ no work). err, when set,
// fails every call.
type normListerStub struct {
	rows  map[[2]string][]application.Component
	err   error
	calls []string
}

// ListByVendorProductNorm implements application.ComponentNormLister.
func (s *normListerStub) ListByVendorProductNorm(_ context.Context, vendorNorm, productNorm string) ([]application.Component, error) {
	s.calls = append(s.calls, vendorNorm+"/"+productNorm)
	if s.err != nil {
		return nil, s.err
	}
	return s.rows[[2]string{vendorNorm, productNorm}], nil
}

// mustAliasRule assembles one enabled alias rule through the domain
// constructor; a failing construction is a test error.
func mustAliasRule(t *testing.T, id string, scope domain.AliasScope, from, to string) domain.AliasRule {
	t.Helper()
	rule, err := domain.NewAliasRule(id, scope, from, to, "test alias", 1)
	if err != nil {
		t.Fatalf("NewAliasRule(%s): %v", id, err)
	}
	return rule
}

func TestCandidateComponentIDsSemiJoinReturnsOnlyRelevantComponents(t *testing.T) {
	// CVE side: (microsoft, windows). Vendor alias microsoft → ms and
	// product alias windows → win must meet components stored under
	// either side of each alias (the closure is symmetric); the disabled
	// alias and the unrelated (oracle, java) component must never
	// surface.
	rules := []domain.AliasRule{
		mustAliasRule(t, "vendor-alias", domain.AliasScopeVendor, "microsoft", "ms"),
		mustAliasRule(t, "product-alias", domain.AliasScopeProduct, "windows", "win"),
		mustAliasRule(t, "disabled-alias", domain.AliasScopeVendor, "microsoft", "microsooft").Disable(),
	}
	lister := &normListerStub{rows: map[[2]string][]application.Component{
		{"microsoft", "windows"}:  {{ID: "comp-canonical"}},
		{"ms", "windows"}:         {{ID: "comp-vendor-alias"}},
		{"microsoft", "win"}:      {{ID: "comp-product-alias"}},
		{"ms", "win"}:             {{ID: "comp-both-aliases"}},
		{"oracle", "java"}:        {{ID: "comp-unrelated"}},
		{"microsooft", "windows"}: {{ID: "comp-disabled-alias"}},
	}}

	got, err := application.CandidateComponentIDs(context.Background(),
		[]application.VendorProductPair{{Vendor: "microsoft", Product: "windows"}}, rules, lister)
	if err != nil {
		t.Fatalf("CandidateComponentIDs: %v", err)
	}
	want := []string{"comp-both-aliases", "comp-canonical", "comp-product-alias", "comp-vendor-alias"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	// The closure expands one pair to the four closed combinations, each
	// queried exactly once, in the deterministic closure order.
	wantCalls := []string{"microsoft/win", "microsoft/windows", "ms/win", "ms/windows"}
	if !reflect.DeepEqual(lister.calls, wantCalls) {
		t.Fatalf("lister calls = %v, want %v", lister.calls, wantCalls)
	}
}

func TestCandidateComponentIDsWithoutCandidatesIsEmpty(t *testing.T) {
	rules := []domain.AliasRule{
		mustAliasRule(t, "vendor-alias", domain.AliasScopeVendor, "microsoft", "ms"),
		mustAliasRule(t, "product-alias", domain.AliasScopeProduct, "windows", "win"),
	}
	lister := &normListerStub{rows: map[[2]string][]application.Component{
		{"microsoft", "windows"}: {{ID: "comp-canonical"}},
	}}
	ctx := context.Background()

	// No pairs at all → empty, and the index is never read.
	got, err := application.CandidateComponentIDs(ctx, nil, rules, lister)
	if err != nil || len(got) != 0 {
		t.Fatalf("no pairs: got (%v, %v), want (empty, nil)", got, err)
	}
	if len(lister.calls) != 0 {
		t.Fatalf("no pairs: lister called %d times, want 0 (no candidate ⇒ no work)", len(lister.calls))
	}

	// A pair with an empty key is absent and matches nothing.
	for name, pairs := range map[string][]application.VendorProductPair{
		"empty vendor":  {{Vendor: "", Product: "windows"}},
		"empty product": {{Vendor: "microsoft", Product: ""}},
		"both empty":    {{Vendor: "", Product: ""}},
	} {
		lister.calls = nil
		got, err := application.CandidateComponentIDs(ctx, pairs, rules, lister)
		if err != nil || len(got) != 0 {
			t.Fatalf("%s: got (%v, %v), want (empty, nil)", name, got, err)
		}
		if len(lister.calls) != 0 {
			t.Fatalf("%s: lister called %d times, want 0", name, len(lister.calls))
		}
	}

	// A pair the inventory does not carry closes and queries but meets
	// nothing → empty set.
	lister.calls = nil
	got, err = application.CandidateComponentIDs(ctx,
		[]application.VendorProductPair{{Vendor: "unknown-vendor", Product: "win"}}, rules, lister)
	if err != nil || len(got) != 0 {
		t.Fatalf("unknown pair: got (%v, %v), want (empty, nil)", got, err)
	}
	if len(lister.calls) == 0 {
		t.Fatal("unknown pair: expected the closed pairs to be queried")
	}
}

func TestCandidateComponentIDsDedupesAndSortsDeterministically(t *testing.T) {
	rules := []domain.AliasRule{
		mustAliasRule(t, "vendor-alias", domain.AliasScopeVendor, "microsoft", "ms"),
		mustAliasRule(t, "product-alias", domain.AliasScopeProduct, "windows", "win"),
	}
	// Every component is reachable from several of the overlapping closed
	// pair sets: the result must hold each component id exactly once.
	lister := &normListerStub{rows: map[[2]string][]application.Component{
		{"microsoft", "windows"}: {{ID: "comp-m"}},
		{"ms", "windows"}:        {{ID: "comp-a"}},
		{"microsoft", "win"}:     {{ID: "comp-z"}},
	}}
	ctx := context.Background()

	inOrder := []application.VendorProductPair{
		{Vendor: "microsoft", Product: "windows"},
		{Vendor: "ms", Product: "windows"},
		{Vendor: "microsoft", Product: "win"},
	}
	shuffled := []application.VendorProductPair{
		{Vendor: "microsoft", Product: "win"},
		{Vendor: "microsoft", Product: "windows"},
		{Vendor: "ms", Product: "windows"},
	}

	want := []string{"comp-a", "comp-m", "comp-z"}
	for name, pairs := range map[string][]application.VendorProductPair{
		"input order":      inOrder,
		"shuffled input":   shuffled,
		"duplicated pairs": append(append([]application.VendorProductPair{}, inOrder...), inOrder...),
	} {
		lister.calls = nil
		got, err := application.CandidateComponentIDs(ctx, pairs, rules, lister)
		if err != nil {
			t.Fatalf("%s: CandidateComponentIDs: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: candidates = %v, want %v", name, got, want)
		}
	}
}

func TestCandidateComponentIDsListerFailureAborts(t *testing.T) {
	rules := []domain.AliasRule{
		mustAliasRule(t, "vendor-alias", domain.AliasScopeVendor, "microsoft", "ms"),
	}
	lister := &normListerStub{err: errNormLister}
	_, err := application.CandidateComponentIDs(context.Background(),
		[]application.VendorProductPair{{Vendor: "microsoft", Product: "windows"}}, rules, lister)
	if !errors.Is(err, errNormLister) {
		t.Fatalf("err = %v, want the lister failure to propagate", err)
	}
	if kind, ok := application.ErrorKindOf(err); !ok || kind != application.KindInfra {
		t.Fatalf("error kind = %q (ok=%v), want %q (a half-read candidate set must not under-match)", kind, ok, application.KindInfra)
	}
}
