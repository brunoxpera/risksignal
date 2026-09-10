package matching_test

// Engine unit tests of the pure matcher (ARCH-003 §3): the exact
// identifier methods over CPE and purl, the container_digest guard rails
// (repository, digest and origin all matter), the demotion ladder of
// missing/ambiguous versions, multi-statement aggregation and the input
// validation of the evaluation.

import (
	"strings"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application/matching"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// run evaluates one statement against one component and fails the test on
// error.
func run(t *testing.T, comp domain.Component, stmt matching.AffectedProduct) matching.Outcome {
	t.Helper()
	out, err := matching.Evaluate(matching.Input{
		CVEID:      "CVE-2026-0001",
		Statements: []matching.AffectedProduct{stmt},
		Component:  comp,
	})
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	return out
}

// TestExactIdentifierOverPURL: the purl identity (type/namespace/name)
// matches and the version is exactly affected.
func TestExactIdentifierOverPURL(t *testing.T) {
	comp := fixtureComponent("comp-purl", domain.ComponentIdentifiers{
		PURL:    "pkg:golang/github.com/acme/widget@1.2.3",
		Version: "1.2.3",
	}, "", "", domain.VersionSchemeSemver)
	out := run(t, comp, matching.AffectedProduct{
		PURL:          "pkg:golang/github.com/acme/widget",
		ExactVersions: []string{"1.2.3"},
	})
	if out.Method != domain.MatchMethodExactIdentifier || out.Confidence != domain.ConfidenceHigh || out.Score != 100 {
		t.Errorf("outcome = %s/%s/%d, want exact_identifier/high/100", out.Method, out.Confidence, out.Score)
	}
	if len(out.Reasons) == 0 || !strings.Contains(out.Reasons[0], "purl") {
		t.Errorf("reasons = %v, want a purl identity reason", out.Reasons)
	}
}

// TestExactIdentifierVersionFromIdentifier: the concrete version carried
// by the statement's own identifier counts as an exactly affected version
// — no separate version expression needed.
func TestExactIdentifierVersionFromIdentifier(t *testing.T) {
	comp := fixtureComponent("comp-purl-v", domain.ComponentIdentifiers{
		PURL:    "pkg:golang/github.com/acme/widget@1.2.3",
		Version: "1.2.3",
	}, "", "", domain.VersionSchemeSemver)
	out := run(t, comp, matching.AffectedProduct{PURL: "pkg:golang/github.com/acme/widget@1.2.3"})
	if out.Method != domain.MatchMethodExactIdentifier {
		t.Errorf("outcome = %s, want exact_identifier (the purl @version is an exact affected version)", out.Method)
	}
}

// TestIdentifierMatchVersionOutsideWindow: the CPE identity matches but
// the version is provably outside the window — no_match.
func TestIdentifierMatchVersionOutsideWindow(t *testing.T) {
	comp := fixtureComponent("comp-cpe-out", domain.ComponentIdentifiers{
		CPE:     cpe2("acme", "widget", "2.5.0"),
		Version: "2.5.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	out := run(t, comp, matching.AffectedProduct{
		CPE: cpe2("acme", "widget", "*"),
		Ranges: []domain.VersionRange{
			{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false},
		},
	})
	if out.Method != domain.MatchMethodNoMatch || out.Confidence != domain.ConfidenceNone || out.Score != 0 {
		t.Errorf("outcome = %s/%s/%d, want no_match/none/0", out.Method, out.Confidence, out.Score)
	}
	if len(out.Reasons) == 0 || !strings.Contains(out.Reasons[0], "outside") {
		t.Errorf("reasons = %v, want a provably-not-affected reason", out.Reasons)
	}
}

// TestIdentifierWildcardNeverMatches: a statement CPE with a wildcard
// vendor or product names any product — it is a name-level statement, not
// an identifier match, so the pair demotes to a candidate.
func TestIdentifierWildcardNeverMatches(t *testing.T) {
	comp := fixtureComponent("comp-wild", domain.ComponentIdentifiers{
		CPE:     cpe2("acme", "widget", "1.2.3"),
		Version: "1.2.3",
	}, "acme", "widget", domain.VersionSchemeSemver)
	wildcard := cpe2("acme", "widget", "*")
	wildcard = strings.Replace(wildcard, ":a:acme:widget:", ":a:acme:*:", 1)
	out := run(t, comp, matching.AffectedProduct{CPE: wildcard})
	if out.Method != domain.MatchMethodCandidate {
		t.Errorf("wildcard statement CPE outcome = %s, want candidate (wildcards never form an identity)", out.Method)
	}
}

// TestContainerDigestRequiresRepositoryDigestAndOrigin: the immutable
// digest pins the artifact only together with the repository origin — a
// digest alone, a different repository or a different registry all fall
// through to weaker evidence.
func TestContainerDigestRequiresRepositoryDigestAndOrigin(t *testing.T) {
	comp := fixtureComponent("comp-img", domain.ComponentIdentifiers{
		Image:   "registry.example.com/acme/widget:1.2.3@" + sha256Hex,
		Digest:  sha256Hex,
		Version: "1.2.3",
	}, "", "", domain.VersionSchemeUnknown)

	good := matching.AffectedProduct{Repository: "registry.example.com/acme/widget", Digest: sha256Hex}
	if out := run(t, comp, good); out.Method != domain.MatchMethodContainerDigest || out.Score != 95 {
		t.Errorf("matching repo+digest outcome = %s/%d, want container_digest/95", out.Method, out.Score)
	}

	wrongDigest := matching.AffectedProduct{
		Repository: "registry.example.com/acme/widget",
		Digest:     "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if out := run(t, comp, wrongDigest); out.Method == domain.MatchMethodContainerDigest {
		t.Error("a different digest must not match container_digest")
	}

	wrongOrigin := matching.AffectedProduct{Repository: "registry.example.com/acme/other", Digest: sha256Hex}
	if out := run(t, comp, wrongOrigin); out.Method == domain.MatchMethodContainerDigest {
		t.Error("a different repository must not match container_digest")
	}

	otherRegistry := matching.AffectedProduct{Repository: "other.example.com/acme/widget", Digest: sha256Hex}
	if out := run(t, comp, otherRegistry); out.Method == domain.MatchMethodContainerDigest {
		t.Error("a different registry must not match container_digest (no registry is ever defaulted)")
	}

	// An unparseable statement repository is a caller error the engine
	// refuses to guess around — it falls through instead of matching.
	badRepo := matching.AffectedProduct{Repository: "UPPER/widget", Digest: sha256Hex}
	if out := run(t, comp, badRepo); out.Method == domain.MatchMethodContainerDigest {
		t.Error("an unparseable statement repository must not match container_digest")
	}
}

// TestAmbiguousWindowDemotes: a bounded window over an unknown version
// scheme cannot be evaluated — the match demotes to
// product_uncertain_version instead of fabricating an ordering.
func TestAmbiguousWindowDemotes(t *testing.T) {
	comp := fixtureComponent("comp-amb", domain.ComponentIdentifiers{
		Vendor:  "acme",
		Product: "widget",
		Version: "1.5.0",
	}, "acme", "widget", domain.VersionSchemeUnknown)
	out := run(t, comp, matching.AffectedProduct{
		Vendor: "acme", Product: "widget",
		Ranges: []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}},
	})
	if out.Method != domain.MatchMethodProductUncertainVersion || out.Confidence != domain.ConfidenceMedium || out.Score != 65 {
		t.Errorf("outcome = %s/%s/%d, want product_uncertain_version/medium/65", out.Method, out.Confidence, out.Score)
	}
	if len(out.Reasons) == 0 || !strings.Contains(out.Reasons[0], "cannot be evaluated") {
		t.Errorf("reasons = %v, want an unevaluable-window reason", out.Reasons)
	}
}

// TestUnboundedWindowCoversEveryVersion: an unbounded window needs no
// ordering — even an unknown scheme can be proven affected.
func TestUnboundedWindowCoversEveryVersion(t *testing.T) {
	comp := fixtureComponent("comp-unb", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "anything",
	}, "acme", "widget", domain.VersionSchemeUnknown)
	out := run(t, comp, matching.AffectedProduct{
		Vendor: "acme", Product: "widget",
		Ranges: []domain.VersionRange{{}}, // unbounded window: every version
	})
	if out.Method != domain.MatchMethodCanonicalProductRange {
		t.Errorf("outcome = %s, want canonical_product_range (unbounded window covers every version)", out.Method)
	}
}

// TestStatementWithoutVersionRelationStaysUncertain: a canonical product
// whose statement names no affected version cannot be confirmed — the
// method is product_uncertain_version, never a fabricated exact match.
func TestStatementWithoutVersionRelationStaysUncertain(t *testing.T) {
	comp := fixtureComponent("comp-nover", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "1.5.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	out := run(t, comp, matching.AffectedProduct{Vendor: "acme", Product: "widget"})
	if out.Method != domain.MatchMethodProductUncertainVersion {
		t.Errorf("outcome = %s, want product_uncertain_version (no affected version named)", out.Method)
	}
}

// TestExactVersionEqualityUsesSchemeOrdering: exact affected versions
// compare under the scheme's ordering, so semver "1.2" equals "1.2.0".
func TestExactVersionEqualityUsesSchemeOrdering(t *testing.T) {
	comp := fixtureComponent("comp-semi", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "1.2.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	out := run(t, comp, matching.AffectedProduct{
		Vendor: "acme", Product: "widget", ExactVersions: []string{"1.2"},
	})
	if out.Method != domain.MatchMethodCanonicalProductRange {
		t.Errorf("outcome = %s, want canonical_product_range (1.2 == 1.2.0 under semver)", out.Method)
	}
}

// TestStrongestStatementWins: when several affected products of one
// vulnerability relate to the component, the strongest evidence wins and
// the reasons of the winner are reported.
func TestStrongestStatementWins(t *testing.T) {
	comp := fixtureComponent("comp-multi", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "1.5.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	weak := matching.AffectedProduct{
		Vendor: "acme", Product: "widget pro",
		Ranges: []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}},
	}
	strong := matching.AffectedProduct{
		Vendor: "acme", Product: "widget",
		Ranges: []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}},
	}
	out, err := matching.Evaluate(matching.Input{
		CVEID: "CVE-2026-0001", Component: comp,
		Statements: []matching.AffectedProduct{weak, strong},
	})
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if out.Method != domain.MatchMethodCanonicalProductRange || out.Score != 80 {
		t.Errorf("outcome = %s/%d, want the strong canonical_product_range/80", out.Method, out.Score)
	}
	for _, r := range out.Reasons {
		if strings.Contains(r, "widget pro") {
			t.Errorf("reasons must describe the winning statement only, got %q", r)
		}
	}
	if len(out.Reasons) == 0 || !strings.Contains(out.Reasons[0], "acme/widget") {
		t.Errorf("reasons = %v, want the winning canonical evidence", out.Reasons)
	}
}

// TestTiedStatementsKeepBothReasons: two statements of the same product
// with different affected windows tie — both windows stay in the audit
// trail.
func TestTiedStatementsKeepBothReasons(t *testing.T) {
	comp := fixtureComponent("comp-tie", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "1.5.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	w1 := matching.AffectedProduct{
		Vendor: "acme", Product: "widget",
		Ranges: []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}},
	}
	w2 := matching.AffectedProduct{
		Vendor: "acme", Product: "widget",
		Ranges: []domain.VersionRange{{Start: "1.4", StartIncluding: true, End: "3.0", EndIncluding: false}},
	}
	out, err := matching.Evaluate(matching.Input{
		CVEID: "CVE-2026-0001", Component: comp,
		Statements: []matching.AffectedProduct{w1, w2},
	})
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if out.Method != domain.MatchMethodCanonicalProductRange {
		t.Errorf("outcome = %s, want canonical_product_range", out.Method)
	}
	if len(out.Reasons) != 2 {
		t.Errorf("reasons = %d entries (%v), want both windows in the audit trail", len(out.Reasons), out.Reasons)
	}
}

// TestNoMatchOnlyWinsWithoutOtherEvidence: a provable negative from one
// statement is overruled by real evidence from another statement of the
// same vulnerability.
func TestNoMatchOnlyWinsWithoutOtherEvidence(t *testing.T) {
	comp := fixtureComponent("comp-neg", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "3.0.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	negative := matching.AffectedProduct{
		Vendor: "acme", Product: "widget",
		Ranges: []domain.VersionRange{{Start: "1.0", StartIncluding: true, End: "2.0", EndIncluding: false}},
	}
	affected := matching.AffectedProduct{
		Vendor: "acme", Product: "widget",
		Ranges: []domain.VersionRange{{Start: "2.5", StartIncluding: true, End: "4.0", EndIncluding: false}},
	}
	out, err := matching.Evaluate(matching.Input{
		CVEID: "CVE-2026-0001", Component: comp,
		Statements: []matching.AffectedProduct{negative, affected},
	})
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}
	if out.Method != domain.MatchMethodCanonicalProductRange {
		t.Errorf("outcome = %s, want canonical_product_range (3.0.0 is affected by the second window)", out.Method)
	}
}

// TestEvaluateValidation covers the input guard rails: empty statements,
// identity-less statements and empty exact versions error instead of
// silently computing.
func TestEvaluateValidation(t *testing.T) {
	comp := fixtureComponent("comp-val", domain.ComponentIdentifiers{
		Vendor: "acme", Product: "widget", Version: "1.0.0",
	}, "acme", "widget", domain.VersionSchemeSemver)
	valid := matching.AffectedProduct{Vendor: "acme", Product: "widget", ExactVersions: []string{"1.0.0"}}

	if _, err := matching.Evaluate(matching.Input{CVEID: "CVE-2026-0001", Component: comp}); err == nil {
		t.Error("an input without statements must error")
	}
	if _, err := matching.Evaluate(matching.Input{
		CVEID: "CVE-2026-0001", Component: comp,
		Statements: []matching.AffectedProduct{{}},
	}); err == nil {
		t.Error("an identity-less statement must error")
	}
	if _, err := matching.Evaluate(matching.Input{
		CVEID: "CVE-2026-0001", Component: comp,
		Statements: []matching.AffectedProduct{{Vendor: "acme", Product: "widget", ExactVersions: []string{" "}}},
	}); err == nil {
		t.Error("an empty exact version must error")
	}
	if _, err := matching.Evaluate(matching.Input{
		CVEID: "CVE-2026-0001", Component: comp,
		Statements: []matching.AffectedProduct{valid},
		AliasRules: []domain.AliasRule{ // a chained ruleset is a data error
			mustAliasRule("ar-a", domain.AliasScopeProduct, "a", "b"),
			mustAliasRule("ar-b", domain.AliasScopeProduct, "b", "c"),
		},
	}); err == nil {
		t.Error("a chained alias ruleset must error")
	}
	if _, err := matching.Evaluate(matching.Input{
		CVEID: "CVE-2026-0001", Component: comp,
		Statements:   []matching.AffectedProduct{valid},
		AliasVersion: -1,
	}); err == nil {
		t.Error("a negative ruleset counter must error")
	}
}

// TestComponentVersionSources: the engine reads the component version
// from version_norm, then the raw version column, then the concrete CPE
// version — the chain a rebuild depends on for identifier-only rows.
func TestComponentVersionSources(t *testing.T) {
	// CPE-carried version only: an identifier-only row still relates its
	// version exactly.
	comp := fixtureComponent("comp-cpe-v", domain.ComponentIdentifiers{
		CPE: cpe2("acme", "widget", "1.2.3"),
	}, "acme", "widget", domain.VersionSchemeSemver)
	out := run(t, comp, matching.AffectedProduct{
		CPE:           cpe2("acme", "widget", "*"),
		ExactVersions: []string{"1.2.3"},
	})
	if out.Method != domain.MatchMethodExactIdentifier {
		t.Errorf("outcome = %s, want exact_identifier (the version came from the component CPE)", out.Method)
	}
}
