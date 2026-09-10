package normalise

import (
	"testing"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Scheme-inference tests (ARCH-003 §2 item 6): the chain purl type → CPE
// → explicit scheme column → version shape → generic/unknown. unknown is
// never an error and never fabricates an ordering.

func infer(purl, cpe, version string, explicit domain.VersionScheme) domain.VersionScheme {
	return InferVersionScheme(domain.ComponentIdentifiers{
		Vendor: "v", Product: "p", Version: version, CPE: cpe, PURL: purl,
	}, explicit)
}

func TestInferVersionSchemePurlHints(t *testing.T) {
	cases := []struct {
		name string
		purl string
		want domain.VersionScheme
	}{
		{"golang purl", "pkg:golang/github.com/gorilla/mux@v1.8.0", domain.VersionSchemeSemver},
		{"npm purl", "pkg:npm/express@4.18.2", domain.VersionSchemeSemver},
		{"deb purl", "pkg:deb/debian/curl@7.0.0-1", domain.VersionSchemeDebian},
		{"rpm purl", "pkg:rpm/redhat/curl@7.0.0-1", domain.VersionSchemeRPM},
		{"maven purl", "pkg:maven/org.apache.commons/commons-lang3@3.4", domain.VersionSchemeMaven},
	}
	for _, tc := range cases {
		if got := infer(tc.purl, "", "1.0", domain.VersionSchemeUnknown); got != tc.want {
			t.Errorf("%s: infer = %s, want %s", tc.name, got, tc.want)
		}
	}
	// A purl hint decides even when the row carries no version: the scheme
	// describes the product's ordering, the missing version demotes the
	// match (ARCH-003 §2: unknown never fabricates an ordering; a mapped
	// purl type is evidence, not fabrication).
	if got := infer("pkg:deb/debian/curl", "", "", domain.VersionSchemeUnknown); got != domain.VersionSchemeDebian {
		t.Errorf("deb purl without version = %s, want debian", got)
	}
}

func TestInferVersionSchemePurlFallthrough(t *testing.T) {
	// Unmapped purl types (pypi, gem, oci, …) yield no hint: inference
	// falls through to CPE/shape instead of guessing an ordering the
	// domain does not implement.
	if got := infer("pkg:pypi/django@4.2.1", "", "4.2.1", domain.VersionSchemeUnknown); got != domain.VersionSchemeGeneric {
		t.Errorf("pypi purl with plain version = %s, want generic", got)
	}
	if got := infer("pkg:pypi/django@2024.1.5", "", "2024.1.5", domain.VersionSchemeUnknown); got != domain.VersionSchemeCalver {
		t.Errorf("pypi purl with calver-shaped version = %s, want calver", got)
	}
	if got := infer("pkg:oci/nginx@sha256:ab", "", "sha256:ab", domain.VersionSchemeUnknown); got != domain.VersionSchemeGeneric {
		t.Errorf("oci purl = %s, want generic", got)
	}
}

func TestInferVersionSchemeCPEHints(t *testing.T) {
	cases := []struct {
		name string
		cpe  string
		want domain.VersionScheme
	}{
		{"debian os", "cpe:2.3:o:debian:debian:10:*:*:*:*:*:*:*", domain.VersionSchemeDebian},
		{"ubuntu os (canonical)", "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*", domain.VersionSchemeDebian},
		{"redhat os", "cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*", domain.VersionSchemeRPM},
		{"fedora os", "cpe:2.3:o:fedora:fedora:38:*:*:*:*:*:*:*", domain.VersionSchemeRPM},
		{"opensuse os", "cpe:2.3:o:opensuse:opensuse:15.4:*:*:*:*:*:*:*", domain.VersionSchemeRPM},
		{"cpe vendor case-insensitive", "cpe:2.3:o:Debian:debian:10:*:*:*:*:*:*:*", domain.VersionSchemeDebian},
	}
	for _, tc := range cases {
		if got := infer("", tc.cpe, "1.0", domain.VersionSchemeUnknown); got != tc.want {
			t.Errorf("%s: infer = %s, want %s", tc.name, got, tc.want)
		}
	}
	// Application CPEs carry no reliable family signal: no hint is
	// fabricated, the shape decides.
	if got := infer("", "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*", "1.2.3", domain.VersionSchemeUnknown); got != domain.VersionSchemeGeneric {
		t.Errorf("application cpe with plain version = %s, want generic", got)
	}
	if got := infer("", "cpe:2.3:a:acme:widget:2024.1.5:*:*:*:*:*:*:*", "2024.1.5", domain.VersionSchemeUnknown); got != domain.VersionSchemeCalver {
		t.Errorf("application cpe with calver-shaped version = %s, want calver", got)
	}
}

func TestInferVersionSchemeExplicit(t *testing.T) {
	// The explicit scheme column sits between CPE and version shape in the
	// chain; unknown (the I3 default, the CSV carries no scheme column) is
	// treated as unset.
	if got := infer("", "", "1.2.3", domain.VersionSchemeSemver); got != domain.VersionSchemeSemver {
		t.Errorf("explicit semver = %s, want semver", got)
	}
	if got := infer("", "", "2024.1.5", domain.VersionSchemeUnknown); got != domain.VersionSchemeCalver {
		t.Errorf("unset explicit must fall through to shape, got %s", got)
	}
	// A purl hint outranks the explicit column (ARCH-003 §2 chain order).
	if got := infer("pkg:deb/debian/curl@7.0", "", "7.0", domain.VersionSchemeSemver); got != domain.VersionSchemeDebian {
		t.Errorf("purl must outrank explicit column, got %s", got)
	}
}

func TestInferVersionSchemeShape(t *testing.T) {
	cases := []struct {
		version string
		want    domain.VersionScheme
	}{
		{"2024.1.5", domain.VersionSchemeCalver},
		{"2024-01-05", domain.VersionSchemeCalver},
		{"20240105", domain.VersionSchemeCalver},
		{"2024.1", domain.VersionSchemeCalver},
		{"2024", domain.VersionSchemeCalver},
		{"1.2.3", domain.VersionSchemeGeneric},
		{"1.2.3-beta.1", domain.VersionSchemeGeneric},
		{"2024.13", domain.VersionSchemeGeneric},   // month 13 out of range
		{"2024.1.32", domain.VersionSchemeGeneric}, // day 32 out of range
		{"20241301", domain.VersionSchemeGeneric},  // compact month 13
		{"abc", domain.VersionSchemeGeneric},
		{"", domain.VersionSchemeUnknown},
		{"   ", domain.VersionSchemeUnknown},
	}
	for _, tc := range cases {
		if got := infer("", "", tc.version, domain.VersionSchemeUnknown); got != tc.want {
			t.Errorf("infer(version %q) = %s, want %s", tc.version, got, tc.want)
		}
	}
}

func TestInferVersionSchemeNoVersion(t *testing.T) {
	// A row without any version has no ordering — unknown, never a
	// fabricated scheme. Digest-only container rows land here.
	ids := domain.ComponentIdentifiers{Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	if got := InferVersionScheme(ids, domain.VersionSchemeUnknown); got != domain.VersionSchemeUnknown {
		t.Errorf("digest-only row = %s, want unknown", got)
	}
}

func TestInferVersionSchemeMalformedIdentifiers(t *testing.T) {
	// A malformed identifier yields no hint (syntax validation is the
	// importer's job, DEV-048); inference falls through and never errors.
	if got := infer("pkg:golang", "", "1.2.3", domain.VersionSchemeUnknown); got != domain.VersionSchemeGeneric {
		t.Errorf("malformed purl must not hint, got %s", got)
	}
	if got := infer("", "cpe:2.3:o:debian", "", domain.VersionSchemeUnknown); got != domain.VersionSchemeUnknown {
		t.Errorf("malformed cpe must not hint, got %s", got)
	}
}

// TestInferredCalverAlwaysOrderable is the mirror proof between the shape
// detector and the DEV-044 calver comparator: every shape this package
// infers as calver must be orderable by CompareCalver (same input twice =>
// equal, no error), so an inferred calver can never blow up range
// evaluation at match time.
func TestInferredCalverAlwaysOrderable(t *testing.T) {
	strategy := domain.StrategyFor(domain.VersionSchemeCalver)
	for _, version := range []string{
		"2024.1.5", "2024-01-05", "20240105", "2024.1", "2024", "2023.12.31", "1999.1.1",
	} {
		if got := infer("", "", version, domain.VersionSchemeUnknown); got != domain.VersionSchemeCalver {
			t.Errorf("shape %q should infer calver, got %s", version, got)
		}
		if ord, err := strategy.Compare(version, version); err != nil || ord != domain.OrderingEqual {
			t.Errorf("CompareCalver(%q, %q) = %v, %v — inferred calver must be orderable", version, version, ord, err)
		}
	}
}
