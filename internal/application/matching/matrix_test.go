package matching_test

// Reference-matrix tests of the I3 matching engine (ARCH-003 §8a,
// WP-3.06): a fixture component of every identifier shape × a synthetic
// affected-product statement for every MatchMethod, asserted per
// (asset_type, method) cell for the exact method/confidence/score and a
// non-empty TR-007 reason list. The matcher is a pure function of the
// component and the statement — the asset type is orthogonal metadata the
// engine never reads — so the matrix proves that an asset of every type
// yields the method-level outcome of its components.
//
// The candidate cell additionally pins the two engine contracts of
// ADR-015: the score is the real, deterministic similarity in the band
// [1, 54] and the confidence is low — fuzzy matching yields candidates
// only and can never produce high confidence.

import (
	"strings"
	"testing"

	"github.com/xpera/risksignal/internal/application/matching"
	"github.com/xpera/risksignal/internal/domain"
)

// methodCell is one reference-matrix cell: the fixture component (of the
// method's identifier shape), the affected-product statement that must
// produce the method, and the derived confidence/score the ADR-015
// mapping fixes for it.
type methodCell struct {
	name   string
	comp   domain.Component
	stmt   matching.AffectedProduct
	rules  []domain.AliasRule
	method domain.MatchMethod
	conf   domain.Confidence
	score  int
}

// sha256Hex is a syntactically valid immutable digest suffix (64 hex
// digits) for the container fixtures.
const sha256Hex = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func cpe2(vendor, product, version string) string {
	return "cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
}

// fixtureComponent assembles one fixture component with the write-time
// comparison keys folded like the import layer folds them.
func fixtureComponent(id string, ids domain.ComponentIdentifiers, vendor, product string, scheme domain.VersionScheme) domain.Component {
	c, err := domain.NewComponent(id, "asset-1", ids, vendor, product, "", scheme)
	if err != nil {
		panic(err)
	}
	return c
}

// mustAliasRule assembles one enabled alias rule or fails the test.
func mustAliasRule(id string, scope domain.AliasScope, from, to string) domain.AliasRule {
	r, err := domain.NewAliasRule(id, scope, from, to, "fixture alias", 1)
	if err != nil {
		panic(err)
	}
	return r
}

// matrixCells is the fixture set of every MatchMethod cell (ARCH-003 §3).
func matrixCells() []methodCell {
	return []methodCell{
		{
			// exact_identifier: the statement pins the component's CPE
			// identity (part/vendor/product) and the version lies in the
			// affected window.
			name: "exact_identifier",
			comp: fixtureComponent("comp-exact", domain.ComponentIdentifiers{
				CPE:     cpe2("acme", "widget", "1.2.3"),
				Version: "1.2.3",
			}, "acme", "widget", domain.VersionSchemeSemver),
			stmt: matching.AffectedProduct{
				CPE: cpe2("acme", "widget", "*"),
				Ranges: []domain.VersionRange{
					{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false},
				},
			},
			method: domain.MatchMethodExactIdentifier,
			conf:   domain.ConfidenceHigh,
			score:  100,
		},
		{
			// container_digest: image repository + immutable digest.
			name: "container_digest",
			comp: fixtureComponent("comp-digest", domain.ComponentIdentifiers{
				Image:   "registry.example.com/acme/widget:1.2.3@" + sha256Hex,
				Digest:  sha256Hex,
				Version: "1.2.3",
			}, "", "", domain.VersionSchemeUnknown),
			stmt: matching.AffectedProduct{
				Repository: "registry.example.com/acme/widget",
				Digest:     sha256Hex,
			},
			method: domain.MatchMethodContainerDigest,
			conf:   domain.ConfidenceHigh,
			score:  95,
		},
		{
			// alias_exact_version: the product only meets through a
			// controlled alias and the version equals an exactly named
			// affected version.
			name: "alias_exact_version",
			comp: fixtureComponent("comp-alias", domain.ComponentIdentifiers{
				Vendor:  "oracle",
				Product: "weblogic server",
				Version: "12.2.1.4",
			}, "oracle", "weblogic server", domain.VersionSchemeGeneric),
			stmt: matching.AffectedProduct{
				Vendor:        "oracle",
				Product:       "weblogic",
				ExactVersions: []string{"12.2.1.4"},
			},
			rules: []domain.AliasRule{
				mustAliasRule("ar-weblogic", domain.AliasScopeProduct, "weblogic", "weblogic server"),
			},
			method: domain.MatchMethodAliasExactVersion,
			conf:   domain.ConfidenceHigh,
			score:  90,
		},
		{
			// canonical_product_range: normalised product equality, the
			// version provably inside the affected window.
			name: "canonical_product_range",
			comp: fixtureComponent("comp-range", domain.ComponentIdentifiers{
				Vendor:  "acme",
				Product: "widget",
				Version: "1.5.0",
			}, "acme", "widget", domain.VersionSchemeSemver),
			stmt: matching.AffectedProduct{
				Vendor:  "acme",
				Product: "widget",
				Ranges: []domain.VersionRange{
					{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false},
				},
			},
			method: domain.MatchMethodCanonicalProductRange,
			conf:   domain.ConfidenceHigh,
			score:  80,
		},
		{
			// product_uncertain_version: the product matches but the
			// component carries no version.
			name: "product_uncertain_version",
			comp: fixtureComponent("comp-uncertain", domain.ComponentIdentifiers{
				Vendor:  "acme",
				Product: "widget",
			}, "acme", "widget", domain.VersionSchemeSemver),
			stmt: matching.AffectedProduct{
				Vendor:  "acme",
				Product: "widget",
				Ranges: []domain.VersionRange{
					{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false},
				},
			},
			method: domain.MatchMethodProductUncertainVersion,
			conf:   domain.ConfidenceMedium,
			score:  65,
		},
		{
			// controlled_alias_only: the product meets only through a
			// controlled alias and the statement names no version.
			name: "controlled_alias_only",
			comp: fixtureComponent("comp-alias-only", domain.ComponentIdentifiers{
				Vendor:  "oracle",
				Product: "weblogic server",
				Version: "12.2.1.4",
			}, "oracle", "weblogic server", domain.VersionSchemeGeneric),
			stmt: matching.AffectedProduct{
				Vendor:  "sun microsystems",
				Product: "weblogic server",
			},
			rules: []domain.AliasRule{
				mustAliasRule("ar-sun", domain.AliasScopeVendor, "sun microsystems", "oracle"),
			},
			method: domain.MatchMethodControlledAliasOnly,
			conf:   domain.ConfidenceMedium,
			score:  55,
		},
		{
			// candidate: no identity or name relation — only weak product
			// name similarity; the score is the real computed similarity.
			name: "candidate",
			comp: fixtureComponent("comp-candidate", domain.ComponentIdentifiers{
				Vendor:  "apache",
				Product: "apache httpd",
				Version: "2.4.62",
			}, "apache", "apache httpd", domain.VersionSchemeGeneric),
			stmt: matching.AffectedProduct{
				Vendor:  "apache",
				Product: "apache http server",
			},
			method: domain.MatchMethodCandidate,
			conf:   domain.ConfidenceLow,
			score:  domain.CandidateSimilarity("apache http server", "apache httpd"),
		},
		{
			// no_match: the product matches but the version is provably
			// outside every affected window.
			name: "no_match",
			comp: fixtureComponent("comp-none", domain.ComponentIdentifiers{
				Vendor:  "acme",
				Product: "widget",
				Version: "3.0.0",
			}, "acme", "widget", domain.VersionSchemeSemver),
			stmt: matching.AffectedProduct{
				Vendor:  "acme",
				Product: "widget",
				Ranges: []domain.VersionRange{
					{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false},
				},
			},
			method: domain.MatchMethodNoMatch,
			conf:   domain.ConfidenceNone,
			score:  0,
		},
	}
}

// assetTypes is the full AssetType vocabulary of the reference matrix
// (ARCH-003 §8a: one asset of each type).
var assetTypes = []domain.AssetType{
	domain.AssetTypeServerVM,
	domain.AssetTypeApplicationFramework,
	domain.AssetTypeContainerImage,
	domain.AssetTypeNetworkSecurity,
	domain.AssetTypeCloudSaaS,
}

// TestReferenceMatrix covers every (asset_type, method) cell of ARCH-003
// §8a at the pure-matcher unit level: the engine must produce the exact
// method/confidence/score of the ADR-015 mapping plus a non-empty TR-007
// reason list for every cell.
func TestReferenceMatrix(t *testing.T) {
	for _, cell := range matrixCells() {
		for _, at := range assetTypes {
			t.Run(string(at)+"/"+cell.name, func(t *testing.T) {
				in := matching.Input{
					CVEID:      "CVE-2026-0001",
					Statements: []matching.AffectedProduct{cell.stmt},
					Component:  cell.comp,
					AliasRules: cell.rules,
				}
				out, err := matching.Evaluate(in)
				if err != nil {
					t.Fatalf("Evaluate: unexpected error: %v", err)
				}
				if out.Method != cell.method {
					t.Errorf("method = %q, want %q", out.Method, cell.method)
				}
				if out.Confidence != cell.conf {
					t.Errorf("confidence = %q, want %q", out.Confidence, cell.conf)
				}
				if out.Score != cell.score {
					t.Errorf("score = %d, want %d", out.Score, cell.score)
				}
				if len(out.Reasons) == 0 {
					t.Error("reasons must not be empty (TR-007)")
				}
				if out.DecisionRuleID != nil || out.AutoMethod != nil {
					t.Error("a purely computed cell must not carry decision-rule state")
				}
			})
		}
	}
}

// TestCandidateCellDeterminismAndBand pins the candidate contracts on the
// matrix cell itself: the score is the deterministic similarity, stays in
// [1, 54] and stays low whatever the similarity.
func TestCandidateCellDeterminismAndBand(t *testing.T) {
	var cell methodCell
	for _, c := range matrixCells() {
		if c.method == domain.MatchMethodCandidate {
			cell = c
		}
	}
	in := matching.Input{CVEID: "CVE-2026-0001", Statements: []matching.AffectedProduct{cell.stmt}, Component: cell.comp, AliasRules: cell.rules}
	first, err := matching.Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if first.Score < 1 || first.Score > 54 {
		t.Fatalf("candidate score = %d, outside the [1, 54] band", first.Score)
	}
	if first.Confidence != domain.ConfidenceLow {
		t.Errorf("candidate confidence = %q, want low (never high)", first.Confidence)
	}
	for i := 0; i < 20; i++ {
		again, err := matching.Evaluate(in)
		if err != nil {
			t.Fatalf("Evaluate: unexpected error: %v", err)
		}
		if again.Score != first.Score || again.Method != first.Method {
			t.Fatalf("candidate evaluation is not deterministic: %d then %d", first.Score, again.Score)
		}
	}
	if reason := first.Reasons[0]; !strings.Contains(reason, "candidate") {
		t.Errorf("candidate reason %q must mark the match as a candidate", reason)
	}
}
