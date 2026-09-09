package domain

import "fmt"

// MatchMethod is how a vulnerability was matched to an inventory component
// (ch. 9.2, ADR-015). The method is the authoritative field of a match:
// confidence and sort-rank score are derived from it through the versioned
// mapping in mapping.go and are never stored or set independently.
//
// ARCH-001 §4 exposes only exact_identifier and canonical_product_range on
// the I1b API surface; the domain carries the full ADR-015 vocabulary so that
// I3 matching grows by adding enum values, not by changing the model.
type MatchMethod string

// Allowed MatchMethod values (ADR-015, ch. 9.2).
const (
	// MatchMethodExactIdentifier: CPE or purl matches and the version lies
	// unambiguously in the affected range.
	MatchMethodExactIdentifier MatchMethod = "exact_identifier"
	// MatchMethodContainerDigest: image repository and immutable digest match
	// with secured evidence.
	MatchMethodContainerDigest MatchMethod = "container_digest"
	// MatchMethodAliasExactVersion: controlled vendor/product alias and exact
	// version match.
	MatchMethodAliasExactVersion MatchMethod = "alias_exact_version"
	// MatchMethodCanonicalProductRange: normalised product matches; version is
	// provably in range.
	MatchMethodCanonicalProductRange MatchMethod = "canonical_product_range"
	// MatchMethodProductUncertainVersion: product matches; version missing or
	// range not unambiguously interpretable.
	MatchMethodProductUncertainVersion MatchMethod = "product_uncertain_version"
	// MatchMethodControlledAliasOnly: controlled alias matches, no version
	// reference.
	MatchMethodControlledAliasOnly MatchMethod = "controlled_alias_only"
	// MatchMethodCandidate: only weak name similarity or incomplete evidence.
	// A candidate is not a confirmed assignment.
	MatchMethodCandidate MatchMethod = "candidate"
	// MatchMethodNoMatch: product or version provably not affected.
	MatchMethodNoMatch MatchMethod = "no_match"
)

// Valid reports whether m is an allowed MatchMethod value.
func (m MatchMethod) Valid() bool {
	switch m {
	case MatchMethodExactIdentifier,
		MatchMethodContainerDigest,
		MatchMethodAliasExactVersion,
		MatchMethodCanonicalProductRange,
		MatchMethodProductUncertainVersion,
		MatchMethodControlledAliasOnly,
		MatchMethodCandidate,
		MatchMethodNoMatch:
		return true
	}
	return false
}

// ParseMatchMethod parses s into a MatchMethod. Unknown values error.
func ParseMatchMethod(s string) (MatchMethod, error) {
	v := MatchMethod(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid MatchMethod %q", s)
	}
	return v, nil
}
