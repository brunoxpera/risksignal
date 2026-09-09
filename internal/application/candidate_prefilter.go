package application

// This file implements the vulnerability → candidate-component pre-filter
// of WP-3.07 (ADR-012, ARCH-003 §4, DEV-062): the alias-closure semi-join
// that turns a vulnerability's normalised (vendor, product) pairs into
// the deduplicated, sorted candidate component set the I3 matcher
// (WP-3.08) evaluates per candidate and the epss_history loader scores.
//
// Pre-filtering is a pure computation over injected inputs — the normalised
// pairs of the CVE side (as the DEV-047 NVD cpe_config decomposition
// yields them), the effective alias rules of the current ruleset version
// and a ComponentNormLister over the inventory product index — with no
// writes. A vulnerability whose pairs meet no component yields the empty
// set and therefore no work (ADR-012). The function is deterministic: the
// same pairs, rules and inventory rows always yield the same ordered
// candidate set, because both the alias closure (normalise.AliasClosure)
// and the result are sorted and deduplicated.
//
// This is the reuse seam of the pre-filter: the matcher use case and the
// epss_history loader both call CandidateComponentIDs with their own pair
// set and lister — neither re-implements the closure or the join. Both
// callers read the alias rules through application.AliasRuleRepo
// (WP-3.06 wires the adapter) and inject the same lister the matcher's
// per-candidate evaluation reads through; nothing else is shared state.

import (
	"context"
	"sort"

	"github.com/xpera/risksignal/internal/application/normalise"
	"github.com/xpera/risksignal/internal/domain"
)

// VendorProductPair is one normalised (vendor, product) comparison-key
// pair of the CVE side (ADR-012): the keys the pre-filter closes and
// semi-joins. Both fields carry the same NFKC + trim + lowercase fold as
// components.vendor_norm/product_norm, as the DEV-047 decomposition of
// the NVD cpe_config produces them. An empty key is an absent identity
// and matches nothing — components.vendor_norm and product_norm are never
// empty under the I3 contract, so an empty key is skipped, never queried.
type VendorProductPair struct {
	Vendor  string // normalised vendor key
	Product string // normalised product key
}

// CandidateComponentIDs computes the candidate component set of a
// vulnerability (ADR-012, ARCH-003 §4). For every given normalised
// (vendor, product) pair it expands the vendor key through the symmetric
// one-hop alias closure of scope vendor and the product key through the
// closure of scope product (normalise.AliasClosure over rules — enabled
// rules only, chains rejected by normalise.ValidateAliasRules before
// matching) and semi-joins every closed (vendor, product) combination
// against components through lister, collecting the returned component
// ids. The semi-join is therefore symmetric by construction: a canonical
// name and its aliases meet whether the CVE side or the component side
// carries the variant, and one pair whose vendor and product both carry
// variants is covered by the cross product of its two closures.
//
// The result is the deduplicated, ascending-sorted set of the matched
// component ids — a vulnerability with no matching component (or no
// pairs at all) yields an empty slice and nil error, i.e. no work
// (ADR-012). Component ids are collected as returned; an id-less row is
// skipped defensively. A lister failure aborts the pre-filter with an
// infrastructure-class error — candidates of a half-read pair set would
// silently under-match.
func CandidateComponentIDs(ctx context.Context, pairs []VendorProductPair, rules []domain.AliasRule, lister ComponentNormLister) ([]string, error) {
	const op = "candidate_prefilter"

	seen := make(map[string]struct{})
	for _, pair := range pairs {
		if pair.Vendor == "" || pair.Product == "" {
			continue // absent key — never query the index with an empty key
		}
		vendors := normalise.AliasClosure(domain.AliasScopeVendor, pair.Vendor, rules)
		products := normalise.AliasClosure(domain.AliasScopeProduct, pair.Product, rules)
		for _, vendor := range vendors {
			for _, product := range products {
				components, err := lister.ListByVendorProductNorm(ctx, vendor, product)
				if err != nil {
					return nil, InfraError(op, err)
				}
				for _, component := range components {
					if component.ID != "" {
						seen[component.ID] = struct{}{}
					}
				}
			}
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
