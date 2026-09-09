package domain

import "fmt"

// VersionScheme is the version ordering scheme of a product version
// (ARCH-003 §2 vulnerabilities/components, ch. 9.1 "Version semantics").
// It is inferred per component at import time (purl type → CPE → explicit
// column → version shape) and per CVE from the affected product's known
// scheme; the domain stores it on Component and evaluates orderings and
// NVD version ranges through the VersionStrategy of the same name
// (version_strategy.go).
//
// unknown is a first-class value, not an error: a version whose scheme
// could not be inferred simply has no ordering — matching demotes such a
// component to product_uncertain_version (medium) or candidate (low) and
// never fabricates an ordering (ARCH-003 §2).
type VersionScheme string

// Allowed VersionScheme values (ARCH-003 §1.2 components.version_scheme
// CHECK enumerates exactly these seven values).
const (
	// VersionSchemeSemver orders by MAJOR.MINOR.PATCH with pre-release and
	// build rules (semver.org); purl golang/npm, CPE.
	VersionSchemeSemver VersionScheme = "semver"
	// VersionSchemeDebian orders by dpkg version compare
	// (epoch:upstream-revision); purl deb, CPE linux:debian.
	VersionSchemeDebian VersionScheme = "debian"
	// VersionSchemeRPM orders by RPM EVR (epoch:version-release, rpmvercmp).
	VersionSchemeRPM VersionScheme = "rpm"
	// VersionSchemeMaven orders by Maven version ordering (ComparableVersion
	// semantics for the documented core).
	VersionSchemeMaven VersionScheme = "maven"
	// VersionSchemeCalver orders by calendar dates (YYYY.MM.DD / YYYYMMDD).
	VersionSchemeCalver VersionScheme = "calver"
	// VersionSchemeGeneric is the fallback: component-wise numeric segments
	// (dpkg-style character ordering over the whole string).
	VersionSchemeGeneric VersionScheme = "generic"
	// VersionSchemeUnknown means no ordering could be inferred: comparisons
	// and range evaluations error instead of fabricating an order.
	VersionSchemeUnknown VersionScheme = "unknown"
)

// Valid reports whether s is an allowed VersionScheme value.
func (s VersionScheme) Valid() bool {
	switch s {
	case VersionSchemeSemver,
		VersionSchemeDebian,
		VersionSchemeRPM,
		VersionSchemeMaven,
		VersionSchemeCalver,
		VersionSchemeGeneric,
		VersionSchemeUnknown:
		return true
	}
	return false
}

// ParseVersionScheme parses s into a VersionScheme. Unknown values error so
// a typo or an out-of-date source cannot silently change ordering semantics.
func ParseVersionScheme(s string) (VersionScheme, error) {
	v := VersionScheme(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid VersionScheme %q", s)
	}
	return v, nil
}
