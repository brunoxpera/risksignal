package normalise

import (
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Reference version fixture set (ARCH-003 §8a, WP-3.04 exit criterion):
// the ordering anchors per VersionScheme and NVD-style range evaluations,
// asserted through the exact seam the matcher will consume — the DEV-044
// domain comparators behind domain.StrategyFor and the domain range
// evaluator domain.InRange. DEV-044 owns and fully tests these comparators
// (internal/domain/version_strategy.go); this table deliberately re-asserts
// a compact anchor set at the application seam so WP-3.06 can trust the
// boundary it programs against, and so this package's inference output
// (which feeds the same strategies) is proven against real orderings.

// fixtureCase is one ordering anchor: Compare(a, b) under the scheme's
// strategy must equal want.
type fixtureCase struct {
	scheme domain.VersionScheme
	a, b   string
	want   domain.Ordering
}

func TestReferenceVersionFixtureSet(t *testing.T) {
	fixtures := []fixtureCase{
		// semver — MAJOR.MINOR.PATCH + pre-release rules.
		{domain.VersionSchemeSemver, "1.0.0", "2.0.0", domain.OrderingLess},
		{domain.VersionSchemeSemver, "1.2.0", "1.10.0", domain.OrderingLess},
		{domain.VersionSchemeSemver, "1.0.0-alpha", "1.0.0", domain.OrderingLess},
		{domain.VersionSchemeSemver, "2.0.0", "1.9.9", domain.OrderingGreater},
		{domain.VersionSchemeSemver, "1.2.3", "1.2.3", domain.OrderingEqual},
		{domain.VersionSchemeSemver, "1.0.0-rc.1", "1.0.0-rc.2", domain.OrderingLess},
		// debian — dpkg compare ([epoch:]upstream[-revision]).
		{domain.VersionSchemeDebian, "1.0-1", "1.0-2", domain.OrderingLess},
		{domain.VersionSchemeDebian, "1.0~rc1", "1.0", domain.OrderingLess},
		{domain.VersionSchemeDebian, "2:1.0", "1:9.9", domain.OrderingGreater},
		{domain.VersionSchemeDebian, "1.0", "1.0-1", domain.OrderingLess},
		// rpm — EVR (epoch:version-release, rpmvercmp).
		{domain.VersionSchemeRPM, "1.0-1", "1.0-2", domain.OrderingLess},
		{domain.VersionSchemeRPM, "1.2", "1.10", domain.OrderingLess},
		{domain.VersionSchemeRPM, "2:1.0", "1:9.9", domain.OrderingGreater},
		// maven — ComparableVersion core ordering.
		{domain.VersionSchemeMaven, "1.0-alpha-1", "1.0", domain.OrderingLess},
		{domain.VersionSchemeMaven, "1.0-snapshot", "1.0", domain.OrderingLess},
		{domain.VersionSchemeMaven, "1.0", "1.0-1", domain.OrderingLess},
		{domain.VersionSchemeMaven, "1.0-1", "1.0-sp-1", domain.OrderingLess},
		{domain.VersionSchemeMaven, "1.0", "1.0.0", domain.OrderingEqual},
		// calver — YYYY.MM.DD / YYYYMMDD.
		{domain.VersionSchemeCalver, "2023.12.31", "2024.1.1", domain.OrderingLess},
		{domain.VersionSchemeCalver, "20240101", "2024.1.1", domain.OrderingEqual},
		{domain.VersionSchemeCalver, "2024.1", "2024.1.5", domain.OrderingLess},
		{domain.VersionSchemeCalver, "2023", "2024", domain.OrderingLess},
		// generic — component-wise numeric segments (fallback).
		{domain.VersionSchemeGeneric, "1.2", "1.10", domain.OrderingLess},
		{domain.VersionSchemeGeneric, "1.0~rc1", "1.0", domain.OrderingLess},
		{domain.VersionSchemeGeneric, "1.0", "1.0a", domain.OrderingLess},
	}
	for _, fc := range fixtures {
		strategy := domain.StrategyFor(fc.scheme)
		if strategy.Scheme() != fc.scheme {
			t.Fatalf("StrategyFor(%s) = %s", fc.scheme, strategy.Scheme())
		}
		got, err := strategy.Compare(fc.a, fc.b)
		if err != nil {
			t.Errorf("%s: Compare(%q, %q): unexpected error: %v", fc.scheme, fc.a, fc.b, err)
			continue
		}
		if got != fc.want {
			t.Errorf("%s: Compare(%q, %q) = %s, want %s", fc.scheme, fc.a, fc.b, got, fc.want)
		}
	}
}

// TestReferenceRangeFixtureSet evaluates NVD-style version windows
// (versionStart/End with including/excluding semantics) through
// domain.InRange — the range evaluator of DEV-044 this package must not
// re-implement, only consume (ARCH-003 §2/§3).
func TestReferenceRangeFixtureSet(t *testing.T) {
	semver := domain.StrategyFor(domain.VersionSchemeSemver)
	rng := func(start string, startInc bool, end string, endInc bool) domain.VersionRange {
		return domain.VersionRange{Start: start, StartIncluding: startInc, End: end, EndIncluding: endInc}
	}
	cases := []struct {
		name    string
		version string
		rng     domain.VersionRange
		want    bool
	}{
		{"inside open window", "1.5.0", rng("1.0.0", true, "2.0.0", false), true},
		{"lower bound excluded", "1.0.0", rng("1.0.0", false, "2.0.0", false), false},
		{"lower bound included", "1.0.0", rng("1.0.0", true, "2.0.0", false), true},
		{"upper bound excluded", "2.0.0", rng("1.0.0", true, "2.0.0", false), false},
		{"upper bound included", "2.0.0", rng("1.0.0", true, "2.0.0", true), true},
		{"below window", "0.9.0", rng("1.0.0", true, "2.0.0", false), false},
		{"above window", "2.5.0", rng("1.0.0", true, "2.0.0", false), false},
		{"unbounded covers everything", "9.9.9", domain.VersionRange{}, true},
	}
	for _, tc := range cases {
		got, err := domain.InRange(tc.version, tc.rng, semver)
		if err != nil {
			t.Errorf("%s: InRange(%q): unexpected error: %v", tc.name, tc.version, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: InRange(%q) = %v, want %v", tc.name, tc.version, got, tc.want)
		}
	}

	// The unknown scheme never fabricates an ordering: an unbounded window
	// contains any non-empty version, but a bounded window errors instead
	// of guessing (ARCH-003 §2 item 6).
	unknown := domain.StrategyFor(domain.VersionSchemeUnknown)
	if got, err := domain.InRange("1.0", domain.VersionRange{}, unknown); err != nil || !got {
		t.Errorf("unbounded window must contain every version under unknown, got %v, %v", got, err)
	}
	if _, err := domain.InRange("1.0", rng("0.5", true, "2.0", false), unknown); err == nil {
		t.Error("bounded window under unknown must error, not guess")
	}
	if _, err := domain.InRange("", domain.VersionRange{}, semver); err == nil {
		t.Error("an empty version is never in range")
	}
}
