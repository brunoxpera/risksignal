package matching

// White-box tests of the version-relation layer (version.go): the
// component version extraction chain and the affected-version
// classification over exact versions and NVD windows (ARCH-003 §2/§3).
// The classification is the heart of the method ladder — an ordering is
// never fabricated and a provable negative is the only no_match.

import (
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// cpe23 renders a CPE 2.3 application binding with a concrete version
// field (test helper of the white-box tests).
func cpe23(vendor, product, version string) string {
	return "cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
}

func mustComponent(t *testing.T, ids domain.ComponentIdentifiers, vendor, product, versionNorm string, scheme domain.VersionScheme) domain.Component {
	t.Helper()
	c, err := domain.NewComponent("c1", "a1", ids, vendor, product, versionNorm, scheme)
	if err != nil {
		t.Fatalf("NewComponent: unexpected error: %v", err)
	}
	return c
}

// TestComponentVersionChain: version_norm wins, then the raw version
// column, then the concrete CPE version, then the purl version; wildcard
// CPE versions are not versions.
func TestComponentVersionChain(t *testing.T) {
	base := domain.ComponentIdentifiers{
		Vendor:  "acme",
		Product: "widget",
		Version: "2.0.0",
		CPE:     cpe23("acme", "widget", "1.0.0"),
		PURL:    "pkg:golang/github.com/acme/widget@0.9.0",
	}
	if got := componentVersion(mustComponent(t, base, "acme", "widget", "", domain.VersionSchemeSemver)); got != "2.0.0" {
		t.Errorf("raw version column = %q, want 2.0.0", got)
	}
	base.Version = ""
	if got := componentVersion(mustComponent(t, base, "acme", "widget", "", domain.VersionSchemeSemver)); got != "1.0.0" {
		t.Errorf("CPE-carried version = %q, want 1.0.0", got)
	}
	base.CPE = cpe23("acme", "widget", "*")
	if got := componentVersion(mustComponent(t, base, "acme", "widget", "", domain.VersionSchemeSemver)); got != "0.9.0" {
		t.Errorf("purl-carried version = %q, want 0.9.0", got)
	}
	base.PURL = ""
	if got := componentVersion(mustComponent(t, base, "acme", "widget", "", domain.VersionSchemeSemver)); got != "" {
		t.Errorf("versionless component = %q, want empty", got)
	}
	nv := mustComponent(t, base, "acme", "widget", "3.0.0", domain.VersionSchemeSemver)
	nv.Version = "2.0.0" // version_norm must win over the raw column
	if got := componentVersion(nv); got != "3.0.0" {
		t.Errorf("version_norm = %q, want it to win (3.0.0)", got)
	}
}

// TestClassifyVersion states over the relation matrix.
func TestClassifyVersion(t *testing.T) {
	semver := domain.StrategyFor(domain.VersionSchemeSemver)
	unknown := domain.StrategyFor(domain.VersionSchemeUnknown)
	window := domain.VersionRange{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}

	cases := []struct {
		name     string
		version  string
		strategy domain.VersionStrategy
		exacts   []string
		ranges   []domain.VersionRange
		want     versionState
	}{
		{"no expression", "1.5.0", semver, nil, nil, versionNoExpression},
		{"empty version with expression", "", semver, []string{"1.5.0"}, nil, versionMissing},
		{"exact hit", "1.5.0", semver, []string{"1.5.0"}, nil, versionAffectedExact},
		{"exact hit via scheme equality", "1.5.0", semver, []string{"1.5"}, nil, versionAffectedExact},
		{"exact miss", "2.5.0", semver, []string{"1.5.0"}, nil, versionProvablyNotAffected},
		{"exact equality without ordering", "1.5.0", unknown, []string{"1.5.0"}, nil, versionAffectedExact},
		{"no ordering: padded miss stays a miss", "1.5.0", unknown, []string{"1.5"}, nil, versionProvablyNotAffected},
		{"range hit", "1.5.0", semver, nil, []domain.VersionRange{window}, versionAffectedRange},
		{"range miss", "2.5.0", semver, nil, []domain.VersionRange{window}, versionProvablyNotAffected},
		{"range miss but exact hit", "2.5.0", semver, []string{"2.5.0"}, []domain.VersionRange{window}, versionAffectedExact},
		{"bounded window over unknown scheme", "1.5.0", unknown, nil, []domain.VersionRange{window}, versionAmbiguous},
		{"unbounded window over unknown scheme", "1.5.0", unknown, nil, []domain.VersionRange{{}}, versionAffectedRange},
		{"both exact and range miss", "3.0.0", semver, []string{"1.0.0"}, []domain.VersionRange{window}, versionProvablyNotAffected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyVersion(tc.version, tc.strategy.Scheme(), tc.exacts, tc.ranges)
			if got.state != tc.want {
				t.Errorf("classifyVersion(%q, %s, %v, %v) = %s, want %s",
					tc.version, tc.strategy.Scheme(), tc.exacts, tc.ranges, got.state, tc.want)
			}
		})
	}
}

// TestClassifyVersionHalfOpenWindows: the window bounds follow the NVD
// including/excluding semantics of the domain evaluator — equality on an
// including bound is inside, on an excluding bound outside.
func TestClassifyVersionHalfOpenWindows(t *testing.T) {
	semver := domain.StrategyFor(domain.VersionSchemeSemver)
	rng := domain.VersionRange{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}
	if got := classifyVersion("1.0", semver.Scheme(), nil, []domain.VersionRange{rng}); got.state != versionAffectedRange {
		t.Errorf("version equal to an including start must be affected, got %s", got.state)
	}
	if got := classifyVersion("2.0", semver.Scheme(), nil, []domain.VersionRange{rng}); got.state != versionProvablyNotAffected {
		t.Errorf("version equal to an excluding end must be outside, got %s", got.state)
	}
}

// TestStatementExactVersions: the concrete version of the statement's own
// identifier joins the explicit exact versions.
func TestStatementExactVersions(t *testing.T) {
	a := AffectedProduct{
		CPE:           cpe23("acme", "widget", "1.2.3"),
		ExactVersions: []string{"1.0.0"},
	}
	got := statementExactVersions(a)
	if len(got) != 2 || got[0] != "1.0.0" || got[1] != "1.2.3" {
		t.Errorf("statementExactVersions = %v, want [1.0.0 1.2.3]", got)
	}
	wild := AffectedProduct{CPE: cpe23("acme", "widget", "*")}
	if got := statementExactVersions(wild); len(got) != 0 {
		t.Errorf("wildcard CPE version must not become an exact version, got %v", got)
	}
	p := AffectedProduct{PURL: "pkg:golang/github.com/acme/widget@2.0.0"}
	if got := statementExactVersions(p); len(got) != 1 || got[0] != "2.0.0" {
		t.Errorf("purl @version must become an exact version, got %v", got)
	}
}

// TestRenderWindow: deterministic window rendering for the TR-007 reasons.
func TestRenderWindow(t *testing.T) {
	cases := []struct {
		r    domain.VersionRange
		want string
	}{
		{domain.VersionRange{}, "any version"},
		{domain.VersionRange{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}, "v >= 1.0 and v < 2.0"},
		{domain.VersionRange{Start: "1.0", StartIncluding: false}, "v > 1.0"},
		{domain.VersionRange{End: "2.0", EndIncluding: true}, "v <= 2.0"},
		{domain.VersionRange{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: true}, "v >= 1.0 and v <= 2.0"},
	}
	for _, tc := range cases {
		if got := renderWindow(tc.r); got != tc.want {
			t.Errorf("renderWindow(%+v) = %q, want %q", tc.r, got, tc.want)
		}
	}
}
