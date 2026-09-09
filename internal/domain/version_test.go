package domain

import (
	"fmt"
	"testing"
)

// Version semantics tests (ARCH-003 §2): the VersionScheme vocabulary, the
// VersionStrategy comparators over fixture tables (semver/debian/rpm/
// maven/calver/generic, never lexicographic), the NVD range evaluator with
// its including/excluding bounds, and deterministic property tests
// (totality, reflexivity, antisymmetry, weak transitivity) over generated
// version populations per scheme.

// TestParseVersionScheme covers every allowed VersionScheme value and
// invalid input handling.
func TestParseVersionScheme(t *testing.T) {
	all := []VersionScheme{
		VersionSchemeSemver,
		VersionSchemeDebian,
		VersionSchemeRPM,
		VersionSchemeMaven,
		VersionSchemeCalver,
		VersionSchemeGeneric,
		VersionSchemeUnknown,
	}
	for _, want := range all {
		got, err := ParseVersionScheme(string(want))
		if err != nil {
			t.Errorf("ParseVersionScheme(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseVersionScheme(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("VersionScheme %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "SEMVER", "deb", "rpm ", "maven2", "unknown2"} {
		if _, err := ParseVersionScheme(s); err == nil {
			t.Errorf("ParseVersionScheme(%q): want error, got nil", s)
		}
	}
	if VersionScheme("").Valid() {
		t.Error("zero-value VersionScheme must not be Valid")
	}
}

// cmpCase is one anchor of a comparator fixture table.
type cmpCase struct {
	a, b string
	want Ordering
}

// wantError marks a case that must fail to parse/compare.
var wantError = Ordering(99)

// TestVersionStrategyFor checks the registry: every allowed scheme yields a
// working strategy, anything else yields the unknown strategy whose
// comparisons error (never nil, never a silent default).
func TestVersionStrategyFor(t *testing.T) {
	// A valid sample version per scheme (calver needs a calendar shape).
	samples := map[VersionScheme]string{
		VersionSchemeSemver:  "1.0.0",
		VersionSchemeDebian:  "1.0",
		VersionSchemeRPM:     "1.0",
		VersionSchemeMaven:   "1.0",
		VersionSchemeCalver:  "2024.1.1",
		VersionSchemeGeneric: "1.0",
	}
	for _, scheme := range []VersionScheme{
		VersionSchemeSemver, VersionSchemeDebian, VersionSchemeRPM,
		VersionSchemeMaven, VersionSchemeCalver, VersionSchemeGeneric,
	} {
		s := StrategyFor(scheme)
		if s.Scheme() != scheme {
			t.Errorf("StrategyFor(%q).Scheme() = %q, want %q", scheme, s.Scheme(), scheme)
		}
		v := samples[scheme]
		if _, err := s.Compare(v, v); err != nil {
			t.Errorf("StrategyFor(%q).Compare(%q, %q): unexpected error: %v", scheme, v, v, err)
		}
	}
	u := StrategyFor(VersionSchemeUnknown)
	if u.Scheme() != VersionSchemeUnknown {
		t.Errorf("StrategyFor(unknown).Scheme() = %q, want unknown", u.Scheme())
	}
	if _, err := u.Compare("1.0", "2.0"); err == nil {
		t.Error("unknown strategy Compare: want error (no ordering), got nil")
	}
	bogus := StrategyFor(VersionScheme("calver "))
	if bogus.Scheme() != VersionSchemeUnknown {
		t.Errorf("StrategyFor(bogus).Scheme() = %q, want unknown", bogus.Scheme())
	}
}

// TestCompareSemverFixtures anchors the semver comparator on semver.org
// precedence rules plus the documented leniencies (v/= prefix, missing
// minor/patch coerced to 0, build metadata ignored).
func TestCompareSemverFixtures(t *testing.T) {
	cases := []cmpCase{
		{"1.2.3", "1.2.3", OrderingEqual},
		{"1.2.3", "1.2.4", OrderingLess},
		{"1.2.3", "1.3.0", OrderingLess},
		{"1.2.3", "2.0.0", OrderingLess},
		{"1.9.0", "1.10.0", OrderingLess}, // numeric, not lexicographic
		{"2.0.0", "1.99.99", OrderingGreater},
		// leniencies: prefix and missing parts
		{"v1.2.3", "1.2.3", OrderingEqual},
		{"V1.2.3", "1.2.3", OrderingEqual},
		{"=1.2.3", "1.2.3", OrderingEqual},
		{"1.2", "1.2.0", OrderingEqual},
		{"1", "1.0.0", OrderingEqual},
		{"01.2.3", "1.2.3", OrderingEqual}, // leading zeros tolerated, numeric
		// pre-release
		{"1.0.0-alpha", "1.0.0", OrderingLess},
		{"1.0.0", "1.0.0-alpha", OrderingGreater},
		{"1.0.0-alpha", "1.0.0-beta", OrderingLess},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", OrderingLess},
		{"1.0.0-alpha.2", "1.0.0-alpha.11", OrderingLess},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", OrderingLess}, // numeric < alphanumeric
		{"1.0.0-alpha.beta", "1.0.0-beta", OrderingLess},
		{"1.0.0-beta.2", "1.0.0-beta.11", OrderingLess},
		{"1.0.0-rc.1", "1.0.0", OrderingLess},
		{"1.0.0-alpha", "1.0.0-alpha.1", OrderingLess}, // larger pre-release set
		{"1.0.0-1", "1.0.0-alpha", OrderingLess},       // numeric identifiers sort first
		// build metadata is ignored for precedence
		{"1.0.0+build.5", "1.0.0", OrderingEqual},
		{"1.0.0-alpha+001", "1.0.0-alpha", OrderingEqual},
	}
	assertCmpCases(t, "semver", cases, CompareSemver)
}

// TestCompareSemverErrors anchors the strict parse side: anything the
// scheme cannot order errors instead of being compared loosely.
func TestCompareSemverErrors(t *testing.T) {
	cases := []cmpCase{
		{"", "1.2.3", wantError},
		{"1.2.3", "", wantError},
		{"1.2.3.4", "1.2.3", wantError},
		{"1.x.3", "1.2.3", wantError},
		{"1.2.3-", "1.2.3", wantError}, // empty pre-release
		{"1.2.3-alpha..1", "1.2.3", wantError},
		{"1.2.3-alpha 1", "1.2.3", wantError},
		{"-alpha", "1.2.3", wantError},
		{"v", "1.2.3", wantError},
	}
	assertCmpCases(t, "semver", cases, CompareSemver)
}

// TestCompareDebianFixtures anchors the dpkg comparator on the classic
// deb-version(7) orderings: ~ before everything, letters before
// non-letters, numeric runs, epochs, revisions.
func TestCompareDebianFixtures(t *testing.T) {
	cases := []cmpCase{
		{"1.0", "1.0", OrderingEqual},
		{"1.0", "2.0", OrderingLess},
		{"0.9.8", "0.9.8a", OrderingLess}, // trailing letters are newer
		{"1.0a", "1.0b", OrderingLess},
		{"1.0", "1.0a", OrderingLess},
		{"1.0~rc1", "1.0", OrderingLess}, // ~ sorts before everything
		{"1.0~rc1", "1.0~rc2", OrderingLess},
		{"1.0~rc1~git123-1", "1.0~rc1", OrderingLess},
		{"1.0~rc1~git123", "1.0~rc1", OrderingLess},
		{"1.0", "1.0-1", OrderingLess}, // a present revision is newer
		{"1.0-1", "1.0-2", OrderingLess},
		{"1.0-1", "1.0-1.1", OrderingLess},
		{"1.0.10", "1.0.9", OrderingGreater}, // numeric runs, not lexicographic
		{"1.0.10", "1.0.100", OrderingLess},
		{"1.01", "1.1", OrderingEqual}, // leading zeros are insignificant
		{"1.5", "1.50", OrderingLess},
		{"1:1.0", "2:0.5", OrderingLess}, // epochs dominate
		{"2:1.0", "1:9.9", OrderingGreater},
		{"1:1.0", "1:1.0-1", OrderingLess},
		{"1.0", "1.0+dfsg1", OrderingLess}, // non-letters sort after letters
	}
	assertCmpCases(t, "debian", cases, CompareDebian)
}

// TestCompareDebianErrors anchors dpkg parse strictness.
func TestCompareDebianErrors(t *testing.T) {
	cases := []cmpCase{
		{"", "1.0", wantError},
		{"1.0", "", wantError},
		{"a:1.0", "1.0", wantError},    // non-numeric epoch
		{":1.0", "1.0", wantError},     // empty epoch
		{"1.0:2.0", "1.0", wantError},  // two colons
		{"-1", "1.0", wantError},       // empty upstream
		{"1.0-", "1.0", OrderingEqual}, // trailing hyphen: empty revision == no revision
	}
	assertCmpCases(t, "debian", cases, CompareDebian)
}

// TestCompareRPMFixtures anchors the rpmvercmp semantics on the classic
// vector set (rpm tests/rpmvercmp.at): tilde, alpha-vs-numeric segments,
// separators ignored, EVR epochs and releases.
func TestCompareRPMFixtures(t *testing.T) {
	cases := []cmpCase{
		{"1.0", "1.0", OrderingEqual},
		{"1.0", "2.0", OrderingLess},
		{"2.0.1", "2.0", OrderingGreater},
		{"2.0", "2.0.1", OrderingLess},
		{"5.5p1", "5.5p2", OrderingLess},
		{"5.5p10", "5.5p1", OrderingGreater},
		{"10xyz", "10.1xyz", OrderingLess}, // numeric segment newer than alpha
		{"xyz10", "xyz10.1", OrderingLess},
		{"xyz.4", "xyz.5", OrderingLess},
		{"xyz.4", "8", OrderingLess},
		{"1.0bar", "1.0foo", OrderingLess},
		{"foo1", "foo1", OrderingEqual},
		{"foo1", "foo2", OrderingLess},
		{"foo1", "foo10", OrderingLess},
		{"1.0a", "1.0b", OrderingLess},
		{"1.0a", "1.0", OrderingGreater}, // remaining content is newer
		{"1.0", "1.0a", OrderingLess},
		{"1.0~rc1", "1.0", OrderingLess},
		{"1.0~rc1", "1.0~rc2", OrderingLess},
		{"1.0", "1.0-1", OrderingLess}, // EVR: release "" < release "1"
		{"1.0-1", "1.0-2", OrderingLess},
		{"1.0-1", "1.0-1.fc35", OrderingLess},
		{"1:1.0", "2:0.5", OrderingLess},
		{"2:1.0", "1:9.9", OrderingGreater},
		{"0.9", "1.0", OrderingLess},
	}
	assertCmpCases(t, "rpm", cases, CompareRPM)
}

// TestCompareRPMErrors anchors EVR parse strictness.
func TestCompareRPMErrors(t *testing.T) {
	cases := []cmpCase{
		{"", "1.0", wantError},
		{"1.0", "", wantError},
		{"x:1.0", "1.0", wantError},
		{"1:2:3.0", "1.0", wantError},
		{":1.0", "1.0", wantError},
	}
	assertCmpCases(t, "rpm", cases, CompareRPM)
}

// TestCompareMavenFixtures anchors the Maven comparator on the documented
// ComparableVersion core chain: numeric padding equality, the qualifier
// order alpha < beta < milestone < rc < snapshot < release < numeric
// builds < sp, and numeric build comparison.
func TestCompareMavenFixtures(t *testing.T) {
	cases := []cmpCase{
		{"1", "1.0", OrderingEqual},
		{"1.0.0", "1", OrderingEqual},
		{"1.0", "1.0.ga", OrderingEqual},
		{"1.0", "1.0.final", OrderingEqual},
		{"1.0", "1.1", OrderingLess},
		{"1.1", "1.2", OrderingLess},
		{"1.2", "1.10", OrderingLess}, // numeric, not lexicographic
		{"1.0-alpha", "1.0-beta", OrderingLess},
		{"1.0-beta", "1.0-milestone", OrderingLess},
		{"1.0-milestone", "1.0-rc", OrderingLess},
		{"1.0-rc", "1.0-snapshot", OrderingLess},
		{"1.0-snapshot", "1.0", OrderingLess},
		{"1.0-alpha-1", "1.0-alpha-2", OrderingLess},
		{"1.0-alpha", "1.0-alpha-1", OrderingLess},
		{"1.0-snapshot-1", "1.0", OrderingLess},
		{"1.0", "1.0-1", OrderingLess}, // numeric builds after the release
		{"1.0-1", "1.0-2", OrderingLess},
		{"1.0-2", "1.0-sp-1", OrderingLess},
		{"1.0-sp-1", "1.0-sp-2", OrderingLess},
		{"1.0-2", "1.0-sp", OrderingLess},
		{"1.0.0-rc1", "1.0.0", OrderingLess},
	}
	assertCmpCases(t, "maven", cases, CompareMaven)
}

// TestCompareMavenErrors: only empty versions error — the maven parser is
// otherwise total over alphanumeric input.
func TestCompareMavenErrors(t *testing.T) {
	cases := []cmpCase{
		{"", "1.0", wantError},
		{"1.0", "", wantError},
	}
	assertCmpCases(t, "maven", cases, CompareMaven)
}

// TestCompareCalverFixtures anchors the calendar comparator: year, then
// month, then day, numerically; the compact YYYYMMDD form equals its
// dotted spelling; absent month/day sort as 0.
func TestCompareCalverFixtures(t *testing.T) {
	cases := []cmpCase{
		{"2024.1.1", "2024.1.1", OrderingEqual},
		{"2023.12.31", "2024.1.1", OrderingLess},
		{"2024.1.1", "2024.1.2", OrderingLess},
		{"2024.1.5", "2024.1.15", OrderingLess}, // numeric day, not lexicographic
		{"2024.1", "2024.2", OrderingLess},
		{"2024.12", "2024.12.31", OrderingLess},
		{"2024", "2024.1", OrderingLess},
		{"2024.1", "2024.1.1", OrderingLess},
		{"2024.12.31", "2025.1.1", OrderingLess},
		{"20240105", "2024.01.05", OrderingEqual}, // compact form
		{"2024.02.01", "2024.2.1", OrderingEqual}, // zero-padded parts
		{"2024-01-05", "2024.1.5", OrderingEqual}, // dash separators
	}
	assertCmpCases(t, "calver", cases, CompareCalver)
}

// TestCompareCalverErrors anchors calver parse strictness: malformed or
// ambiguous shapes error (they fall back to another scheme at the
// boundary) instead of being half-ordered.
func TestCompareCalverErrors(t *testing.T) {
	cases := []cmpCase{
		{"", "2024.1.1", wantError},
		{"24.04", "2024.1", wantError},   // two-digit year: ambiguous, rejected
		{"2024.13", "2024.1", wantError}, // month 13
		{"2024.1.32", "2024.1.1", wantError},
		{"2024.1.1.1", "2024.1.1", wantError}, // four parts
		{"2024a", "2024", wantError},
		{"20241", "2024", wantError}, // five digits: neither year nor compact
	}
	assertCmpCases(t, "calver", cases, CompareCalver)
}

// TestCompareGenericFixtures anchors the generic fallback (dpkg-style
// character ordering over the whole string): numeric runs, tilde,
// letters-before-non-letters, no lexicographic fallback anywhere.
func TestCompareGenericFixtures(t *testing.T) {
	cases := []cmpCase{
		{"1.0", "1.0", OrderingEqual},
		{"1.2", "1.10", OrderingLess},
		{"1.0.10", "1.0.9", OrderingGreater},
		{"2.0.1", "2.0", OrderingGreater},
		{"1.0~rc1", "1.0", OrderingLess},
		{"1.0", "1.0a", OrderingLess},
		{"1.0a", "1.0b", OrderingLess},
		{"1.0a", "1.0.1", OrderingLess}, // letters sort before non-letters
		{"1.0", "1.00", OrderingEqual},  // leading zeros stripped per run
		{"1.5", "1.50", OrderingLess},
		{"1.0-1", "1.0.1", OrderingLess}, // '-' (301) sorts before '.' (302)
		{"1.0+dfsg1", "1.0", OrderingGreater},
		{"a.10", "a.9", OrderingGreater},
	}
	assertCmpCases(t, "generic", cases, CompareGeneric)
}

// TestCompareGenericErrors: only empty versions error — the generic
// comparator is otherwise total.
func TestCompareGenericErrors(t *testing.T) {
	cases := []cmpCase{
		{"", "1.0", wantError},
		{"1.0", "", wantError},
		{"   ", "1.0", wantError},
	}
	assertCmpCases(t, "generic", cases, CompareGeneric)
}

// assertCmpCases runs one fixture table through a comparator.
func assertCmpCases(t *testing.T, name string, cases []cmpCase, cmp func(a, b string) (Ordering, error)) {
	t.Helper()
	for _, c := range cases {
		got, err := cmp(c.a, c.b)
		if c.want == wantError {
			if err == nil {
				t.Errorf("%s: Compare(%q, %q): want error, got %s", name, c.a, c.b, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Compare(%q, %q): unexpected error: %v", name, c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: Compare(%q, %q) = %s, want %s", name, c.a, c.b, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// NVD range evaluator
// ---------------------------------------------------------------------------

// TestInRangeSemver exercises the NVD range evaluator over the semver
// scheme: versionStart/versionEnd with including/excluding semantics,
// boundary equality under semver coercion, open bounds and errors.
func TestInRangeSemver(t *testing.T) {
	strat := StrategyFor(VersionSchemeSemver)
	cases := []struct {
		name    string
		version string
		rng     VersionRange
		want    bool
		wantErr bool
	}{
		{
			name:    "inside",
			version: "1.5.0",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true, End: "2.0.0"},
			want:    true,
		},
		{
			name:    "below start",
			version: "0.9.9",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true, End: "2.0.0"},
			want:    false,
		},
		{
			name:    "at excluded end",
			version: "2.0.0",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true, End: "2.0.0"},
			want:    false,
		},
		{
			name:    "at included end",
			version: "2.0.0",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true, End: "2.0.0", EndIncluding: true},
			want:    true,
		},
		{
			name:    "at included start",
			version: "1.0.0",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true, End: "2.0.0"},
			want:    true,
		},
		{
			name:    "at excluded start",
			version: "1.0.0",
			rng:     VersionRange{Start: "1.0.0", End: "2.0.0"},
			want:    false,
		},
		{
			name:    "start spelled shorter, semver coercion",
			version: "1.0.0",
			rng:     VersionRange{Start: "1.0", StartIncluding: true, End: "2.0.0"},
			want:    true,
		},
		{
			name:    "only upper bound excluding",
			version: "1.9.9",
			rng:     VersionRange{End: "2.0.0"},
			want:    true,
		},
		{
			name:    "only upper bound excluding at bound",
			version: "2.0.0",
			rng:     VersionRange{End: "2.0.0"},
			want:    false,
		},
		{
			name:    "only lower bound including",
			version: "3.0.0",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true},
			want:    true,
		},
		{
			name:    "unbounded",
			version: "9.9.9",
			rng:     VersionRange{},
			want:    true,
		},
		{
			name:    "empty version errors",
			version: "",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true},
			wantErr: true,
		},
		{
			name:    "unparseable bound errors",
			version: "1.5.0",
			rng:     VersionRange{Start: "banana", StartIncluding: true},
			wantErr: true,
		},
		{
			name:    "unparseable version errors",
			version: "not.a.version",
			rng:     VersionRange{Start: "1.0.0", StartIncluding: true},
			wantErr: true,
		},
	}
	for _, c := range cases {
		got, err := InRange(c.version, c.rng, strat)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: InRange(%q, %+v): want error, got %v", c.name, c.version, c.rng, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: InRange(%q, %+v): unexpected error: %v", c.name, c.version, c.rng, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: InRange(%q, %+v) = %v, want %v", c.name, c.version, c.rng, got, c.want)
		}
	}
}

// TestInRangeOtherSchemes checks range evaluation over debian/rpm/maven/
// calver/generic bounds and the unknown-scheme behaviour (bounded ranges
// error — no ordering may be fabricated; unbounded ranges are scheme-free
// and contain any non-empty version).
func TestInRangeOtherSchemes(t *testing.T) {
	cases := []struct {
		name    string
		scheme  VersionScheme
		version string
		rng     VersionRange
		want    bool
		wantErr bool
	}{
		{
			name:    "debian revision inside window",
			scheme:  VersionSchemeDebian,
			version: "1.0-2",
			rng:     VersionRange{Start: "1.0", StartIncluding: true, End: "1.1"},
			want:    true,
		},
		{
			name:    "debian below window",
			scheme:  VersionSchemeDebian,
			version: "0.9",
			rng:     VersionRange{Start: "1.0", StartIncluding: true, End: "1.1"},
			want:    false,
		},
		{
			name:    "rpm at excluded end",
			scheme:  VersionSchemeRPM,
			version: "2.0-1",
			rng:     VersionRange{Start: "1.0", StartIncluding: true, End: "2.0-1"},
			want:    false,
		},
		{
			name:    "rpm prerelease below",
			scheme:  VersionSchemeRPM,
			version: "1.0~rc1",
			rng:     VersionRange{Start: "1.0", StartIncluding: true, End: "2.0"},
			want:    false,
		},
		{
			name:    "maven milestone inside",
			scheme:  VersionSchemeMaven,
			version: "1.0-milestone-1",
			rng:     VersionRange{Start: "1.0-alpha", StartIncluding: true, End: "1.0"},
			want:    true,
		},
		{
			name:    "calver inside",
			scheme:  VersionSchemeCalver,
			version: "2024.06.15",
			rng:     VersionRange{Start: "2024.01.01", StartIncluding: true, End: "2025.01.01"},
			want:    true,
		},
		{
			name:    "generic tilde window",
			scheme:  VersionSchemeGeneric,
			version: "1.5",
			rng:     VersionRange{Start: "1.0~rc1", StartIncluding: true, End: "1.10"},
			want:    true,
		},
		{
			name:    "generic above end",
			scheme:  VersionSchemeGeneric,
			version: "1.10",
			rng:     VersionRange{Start: "1.0", StartIncluding: true, End: "1.10"},
			want:    false,
		},
		{
			name:    "unknown scheme bounded errors",
			scheme:  VersionSchemeUnknown,
			version: "1.5",
			rng:     VersionRange{Start: "1.0", StartIncluding: true},
			wantErr: true,
		},
		{
			name:    "unknown scheme unbounded is scheme-free",
			scheme:  VersionSchemeUnknown,
			version: "1.5",
			rng:     VersionRange{},
			want:    true,
		},
	}
	for _, c := range cases {
		got, err := InRange(c.version, c.rng, StrategyFor(c.scheme))
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: InRange: want error, got %v", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: InRange(%q, %+v): unexpected error: %v", c.name, c.version, c.rng, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: InRange(%q, %+v) = %v, want %v", c.name, c.version, c.rng, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Deterministic property tests
// ---------------------------------------------------------------------------

// xorshift64 is a small deterministic PRNG so the property runs are
// reproducible without external dependencies.
type xorshift64 struct{ s uint64 }

func newXorshift64(seed uint64) *xorshift64 { return &xorshift64{s: seed} }

func (r *xorshift64) next() uint64 {
	x := r.s
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.s = x
	return x
}

func (r *xorshift64) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n))
}

func (r *xorshift64) pick(xs []string) string { return xs[r.intn(len(xs))] }

func (r *xorshift64) digits(maxLen int) string {
	n := 1 + r.intn(maxLen)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + r.intn(10))
	}
	return string(b)
}

// genSemver builds parseable semver-shaped strings.
func (r *xorshift64) genSemver() string {
	pre := []string{"", "", "", "-alpha", "-beta", "-rc.1", "-snapshot", "-alpha.1", "-1", "-2", "-rc.1+build7"}
	s := fmt.Sprintf("%d.%d.%d", r.intn(4), r.intn(20), r.intn(30)) + r.pick(pre)
	if r.intn(4) == 0 {
		s = "v" + s
	}
	return s
}

// genDebian builds parseable dpkg-shaped strings.
func (r *xorshift64) genDebian() string {
	upstream := []string{"0.9", "1.0", "1.0a", "1.0b", "1.0~rc1", "1.0~rc1~git123", "1.01", "1.50", "2.1", "5.5p1", "2.6.32", "1.0.10", "0.9.8a"}
	s := r.pick(upstream)
	switch r.intn(3) {
	case 0:
		s += "-" + r.digits(1)
	case 1:
		s += "-1.1"
	}
	if r.intn(3) == 0 {
		s = fmt.Sprintf("%d:", r.intn(3)) + s
	}
	return s
}

// genRPM builds parseable EVR-shaped strings.
func (r *xorshift64) genRPM() string {
	version := []string{"1.0", "2.0", "2.0.1", "5.5p1", "5.5p10", "1.0a", "1.0bar", "10xyz", "xyz.4", "1.0~rc1", "0.9", "1.0.10", "1.00", "1.01", "2.6.32"}
	s := r.pick(version)
	switch r.intn(3) {
	case 0:
		s += "-" + r.pick([]string{"1", "2", "rc1", "1.fc35"})
	case 1:
		s += "-" + r.digits(1) + "." + r.digits(1)
	}
	if r.intn(3) == 0 {
		s = fmt.Sprintf("%d:", r.intn(3)) + s
	}
	return s
}

// genMaven builds parseable Maven-shaped strings.
func (r *xorshift64) genMaven() string {
	n := 1 + r.intn(3)
	core := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			core += "."
		}
		core += fmt.Sprintf("%d", r.intn(20))
	}
	qual := []string{"", "", "-alpha", "-beta", "-milestone", "-rc", "-snapshot", "-sp", "-ga", "-final", "-1", "-2", "-rc1", "-foo"}
	return core + r.pick(qual)
}

// genCalver builds parseable calendar-shaped strings.
func (r *xorshift64) genCalver() string {
	year := 2000 + r.intn(30)
	month := 1 + r.intn(12)
	day := 1 + r.intn(28)
	sep := r.pick([]string{".", ".", "-"})
	switch r.intn(4) {
	case 0:
		return fmt.Sprintf("%d", year)
	case 1:
		return fmt.Sprintf("%d%s%02d", year, sep, month)
	case 2:
		return fmt.Sprintf("%d%s%02d%s%02d", year, sep, month, sep, day)
	default:
		return fmt.Sprintf("%04d%02d%02d", year, month, day)
	}
}

// genGeneric builds arbitrary non-empty ASCII strings (the generic
// comparator is total over them).
func (r *xorshift64) genGeneric() string {
	pool := "0123456789abcdefghijklmnopqrstuvwxyz~.-+_:"
	n := 1 + r.intn(8)
	b := make([]byte, n)
	for i := range b {
		b[i] = pool[r.intn(len(pool))]
	}
	return string(b)
}

// schemeProperties runs the ordering properties over one scheme: totality
// and reflexivity over singles, antisymmetry over pairs and weak
// transitivity over triples of generated versions.
func schemeProperties(t *testing.T, name string, strat VersionStrategy, gen func(*xorshift64) string) {
	t.Helper()
	rng := newXorshift64(0x5EED ^ uint64(len(name)))
	singles := 100
	pairs := 1500
	triples := 1500

	for i := 0; i < singles; i++ {
		x := gen(rng)
		got, err := strat.Compare(x, x)
		if err != nil {
			t.Fatalf("%s: Compare(%q, %q): unexpected error: %v", name, x, x, err)
		}
		if got != OrderingEqual {
			t.Fatalf("%s: reflexivity violated: Compare(%q, %q) = %s", name, x, x, got)
		}
	}

	for i := 0; i < pairs; i++ {
		a, b := gen(rng), gen(rng)
		ab, err := strat.Compare(a, b)
		if err != nil {
			t.Fatalf("%s: Compare(%q, %q): unexpected error: %v", name, a, b, err)
		}
		ba, err := strat.Compare(b, a)
		if err != nil {
			t.Fatalf("%s: Compare(%q, %q): unexpected error: %v", name, b, a, err)
		}
		if ab != -ba {
			t.Fatalf("%s: antisymmetry violated: Compare(%q,%q)=%s but Compare(%q,%q)=%s",
				name, a, b, ab, b, a, ba)
		}
	}

	for i := 0; i < triples; i++ {
		a, b, c := gen(rng), gen(rng), gen(rng)
		ab, err := strat.Compare(a, b)
		if err != nil {
			t.Fatalf("%s: Compare(%q, %q): unexpected error: %v", name, a, b, err)
		}
		bc, err := strat.Compare(b, c)
		if err != nil {
			t.Fatalf("%s: Compare(%q, %q): unexpected error: %v", name, b, c, err)
		}
		ac, err := strat.Compare(a, c)
		if err != nil {
			t.Fatalf("%s: Compare(%q, %q): unexpected error: %v", name, a, c, err)
		}
		if ab != OrderingGreater && bc != OrderingGreater && ac == OrderingGreater {
			t.Fatalf("%s: transitivity violated: %q <= %q <= %q but Compare(%q,%q)=%s",
				name, a, b, c, a, c, ac)
		}
	}
}

// TestVersionStrategyProperties runs the ordering properties per scheme
// over deterministic generated populations.
func TestVersionStrategyProperties(t *testing.T) {
	props := []struct {
		name   string
		scheme VersionScheme
		gen    func(*xorshift64) string
	}{
		{"semver", VersionSchemeSemver, (*xorshift64).genSemver},
		{"debian", VersionSchemeDebian, (*xorshift64).genDebian},
		{"rpm", VersionSchemeRPM, (*xorshift64).genRPM},
		{"maven", VersionSchemeMaven, (*xorshift64).genMaven},
		{"calver", VersionSchemeCalver, (*xorshift64).genCalver},
		{"generic", VersionSchemeGeneric, (*xorshift64).genGeneric},
	}
	for _, p := range props {
		t.Run(p.name, func(t *testing.T) {
			schemeProperties(t, p.name, StrategyFor(p.scheme), p.gen)
		})
	}
}

// TestOrderingString reports the Ordering rendering used in messages.
func TestOrderingString(t *testing.T) {
	if OrderingLess.String() != "<" || OrderingEqual.String() != "=" || OrderingGreater.String() != ">" {
		t.Errorf("Ordering.String rendering changed: %q %q %q", OrderingLess, OrderingEqual, OrderingGreater)
	}
}
