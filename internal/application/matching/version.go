package matching

import (
	"fmt"
	"strings"

	"github.com/brunoxpera/risksignal/internal/application/normalise"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file implements the affected-version relation of ARCH-003 §3: the
// component's version against one statement's affected-version expression
// (exact affected versions and/or NVD ranges), evaluated through the
// domain's pure comparators and range evaluator (DEV-044) — never through
// a lexicographic string compare (TRI-02) and never fabricating an
// ordering (an unknown version scheme demotes instead of guessing,
// ARCH-003 §2).

// versionState classifies the relation of one component version to one
// affected-version expression.
type versionState uint8

const (
	// versionNoExpression: the statement carries no affected-version
	// expression at all — there is no version relation to establish.
	versionNoExpression versionState = iota
	// versionAffectedExact: the version equals an exactly named affected
	// version.
	versionAffectedExact
	// versionAffectedRange: the version lies inside an affected window.
	versionAffectedRange
	// versionProvablyNotAffected: the version is present, every condition
	// of the expression was decidable and none matched — the one provable
	// negative.
	versionProvablyNotAffected
	// versionMissing: the expression exists but the component carries no
	// version — affectedness cannot be determined.
	versionMissing
	// versionAmbiguous: the expression exists and the version is present,
	// but a condition could not be evaluated (unknown scheme over a
	// bounded window, or a version the scheme cannot order) — the match
	// demotes instead of guessing.
	versionAmbiguous
)

// String renders the state for reasons and diagnostics.
func (s versionState) String() string {
	switch s {
	case versionNoExpression:
		return "no version expression"
	case versionAffectedExact:
		return "affected (exact version)"
	case versionAffectedRange:
		return "affected (in window)"
	case versionProvablyNotAffected:
		return "provably not affected"
	case versionMissing:
		return "version missing"
	default:
		return "ambiguous"
	}
}

// versionRelation is the outcome of relating one component version to one
// statement expression: the classified state plus the exact version or
// window that matched (for the affected states) so the caller can render
// the TR-007 reason precisely.
type versionRelation struct {
	state versionState

	matchedExact string              // the affected version that matched (versionAffectedExact)
	matchedRange domain.VersionRange // the window that matched (versionAffectedRange)
}

// componentVersion extracts the version the matching engine relates to an
// affected-version expression (ARCH-003 §1.2: the comparison key first,
// then the verbatim version column, then the version carried by the
// strongest identifier). The chain is deterministic:
//
//	version_norm → version → concrete CPE version → purl version
//
// and stops at the first non-empty value; "" means the component carries
// no version. A CPE "*"/"-" version is a wildcard, not a version.
func componentVersion(c domain.Component) string {
	if v := strings.TrimSpace(c.VersionNorm); v != "" {
		return v
	}
	if v := strings.TrimSpace(c.Version); v != "" {
		return v
	}
	if cpe, err := normalise.ParseCPE23(strings.TrimSpace(c.CPE)); err == nil {
		if v := strings.TrimSpace(cpe.Version); v != "" && v != "*" && v != "-" {
			return v
		}
	}
	if purl, err := normalise.ParsePURL(strings.TrimSpace(c.PURL)); err == nil {
		if v := strings.TrimSpace(purl.Version); v != "" {
			return v
		}
	}
	return ""
}

// statementExactVersions folds the concrete versions carried by the
// statement's own CPE/purl identifiers into the exact-version list: a
// statement pinning cpe:2.3:a:acme:widget:1.2.3 (or a purl with @1.2.3)
// names 1.2.3 as exactly affected — the identifier's version is part of
// the statement, not of the identity comparison (identity is
// part/vendor/product resp. type/namespace/name, see evaluate.go).
func statementExactVersions(a AffectedProduct) []string {
	exacts := make([]string, 0, len(a.ExactVersions)+1)
	for _, v := range a.ExactVersions {
		exacts = append(exacts, strings.TrimSpace(v))
	}
	if cpe, err := normalise.ParseCPE23(strings.TrimSpace(a.CPE)); err == nil {
		if v := strings.TrimSpace(cpe.Version); v != "" && v != "*" && v != "-" {
			exacts = append(exacts, v)
		}
	} else if purl, err := normalise.ParsePURL(strings.TrimSpace(a.PURL)); err == nil {
		if v := strings.TrimSpace(purl.Version); v != "" {
			exacts = append(exacts, v)
		}
	}
	return exacts
}

// versionEqual reports whether two versions are the same version under
// the scheme's ordering: the strategy's Compare (so semver "1.2" equals
// "1.2.0") when the scheme can order, plain string equality otherwise.
// Equality never needs an ordering and is always decidable — a version
// the scheme cannot parse is simply not equal.
func versionEqual(a, b string, strategy domain.VersionStrategy) bool {
	if a == b {
		return true
	}
	if strategy.Scheme() == domain.VersionSchemeUnknown {
		return false
	}
	ord, err := strategy.Compare(a, b)
	if err != nil {
		return false
	}
	return ord == domain.OrderingEqual
}

// classifyVersion relates one component version to one affected-version
// expression under the component's version scheme (the statement versions
// are versions of the same product line and order under the component's
// scheme). Exact conditions are always decidable; a range condition is
// decidable only when the scheme can order the bound comparison or the
// window is unbounded (an unbounded window covers every non-empty
// version without any ordering — ARCH-003 §2). An empty version with a
// present expression is versionMissing, never "in range".
func classifyVersion(version string, scheme domain.VersionScheme, exacts []string, ranges []domain.VersionRange) versionRelation {
	hasExpr := len(exacts) > 0 || len(ranges) > 0
	if !hasExpr {
		return versionRelation{state: versionNoExpression}
	}
	if version == "" {
		return versionRelation{state: versionMissing}
	}
	strategy := domain.StrategyFor(scheme)
	orderable := scheme != domain.VersionSchemeUnknown

	for _, e := range exacts {
		if versionEqual(version, e, strategy) {
			return versionRelation{state: versionAffectedExact, matchedExact: e}
		}
	}
	undecidable := false
	for _, rng := range ranges {
		if rng.Start == "" && rng.End == "" {
			// Unbounded window: every non-empty version is affected.
			return versionRelation{state: versionAffectedRange, matchedRange: rng}
		}
		if !orderable {
			// A bounded window over a scheme without ordering can never
			// be decided — demote instead of fabricating a result.
			undecidable = true
			continue
		}
		in, err := domain.InRange(version, rng, strategy)
		if err != nil {
			// The version or a bound is not orderable under the scheme.
			undecidable = true
			continue
		}
		if in {
			return versionRelation{state: versionAffectedRange, matchedRange: rng}
		}
	}
	if undecidable {
		return versionRelation{state: versionAmbiguous}
	}
	return versionRelation{state: versionProvablyNotAffected}
}

// renderWindow renders one affected window deterministically for the
// TR-007 reasons: "v >= 1.0 and v < 2.0" style, "any version" for an
// unbounded window.
func renderWindow(r domain.VersionRange) string {
	if r.Start == "" && r.End == "" {
		return "any version"
	}
	var parts []string
	if r.Start != "" {
		if r.StartIncluding {
			parts = append(parts, "v >= "+r.Start)
		} else {
			parts = append(parts, "v > "+r.Start)
		}
	}
	if r.End != "" {
		if r.EndIncluding {
			parts = append(parts, "v <= "+r.End)
		} else {
			parts = append(parts, "v < "+r.End)
		}
	}
	return strings.Join(parts, " and ")
}

// versionAffectedNote renders the affected-version half of a reason for a
// positive relation.
func versionAffectedNote(rel versionRelation) string {
	switch rel.state {
	case versionAffectedExact:
		return fmt.Sprintf("version equals the affected version %s", rel.matchedExact)
	case versionAffectedRange:
		return fmt.Sprintf("version lies in the affected window %s", renderWindow(rel.matchedRange))
	default:
		return rel.state.String()
	}
}
