package normalise

import (
	"strings"

	"github.com/xpera/risksignal/internal/domain"
)

// This file implements the version-scheme inference of ARCH-003 §2 item 6:
// per component at import, the ordering scheme is inferred along the chain
//
//	purl type → CPE → explicit scheme column → version shape → generic/unknown
//
// (ch. 9.1 "Version semantics"). Inference only *selects* one of the
// domain's VersionScheme values; the ordering itself — the comparators and
// the NVD range evaluator — stays entirely with DEV-044's pure
// VersionStrategy implementations (internal/domain/version_strategy.go).
// This file never re-implements an ordering.
//
// unknown is a first-class result, not an error (ARCH-003 §2): a row whose
// scheme cannot be inferred simply has no ordering and matching demotes it.
// Inference only ever returns unknown for a row with no version at all —
// every non-empty version is at least generically orderable, and an
// explicitly forced scheme always wins over shape. unknown never
// fabricates an ordering.

// InferVersionScheme infers the ordering scheme of one inventory row
// (ARCH-003 §2 item 6, ch. 9.1). The chain:
//
//  1. purl — a parseable purl whose type maps onto a scheme (PURLSchemeHint)
//     decides first: the purl type is the primary hint (ARCH-003 §2 item 4).
//  2. CPE — otherwise a parseable CPE whose operating-system part carries a
//     known package family decides (cpeSchemeHint).
//  3. explicit — otherwise an explicit scheme column ("" or
//     VersionSchemeUnknown when unset — the I3 CSV carries no scheme
//     column, so import passes unknown).
//  4. version shape — otherwise a non-empty version shaped like a calendar
//     version infers calver; any other non-empty version infers the
//     generic fallback ordering.
//  5. unknown — a row without a version has no ordering.
//
// An unparseable purl/CPE yields no hint (identifier syntax validation is
// the importer's job; inference only consumes what parses), and raw
// identifiers are never modified here.
func InferVersionScheme(ids domain.ComponentIdentifiers, explicit domain.VersionScheme) domain.VersionScheme {
	if p, err := ParsePURL(strings.TrimSpace(ids.PURL)); err == nil {
		if hint, ok := PURLSchemeHint(p.Type); ok {
			return hint
		}
	}
	if c, err := ParseCPE23(strings.TrimSpace(ids.CPE)); err == nil {
		if hint, ok := cpeSchemeHint(c); ok {
			return hint
		}
	}
	if explicit.Valid() && explicit != domain.VersionSchemeUnknown {
		return explicit
	}
	version := strings.TrimSpace(ids.Version)
	if version == "" {
		return domain.VersionSchemeUnknown
	}
	if isCalverShape(version) {
		return domain.VersionSchemeCalver
	}
	return domain.VersionSchemeGeneric
}

// purlSchemeHints maps the purl types whose ecosystem ordering is one of
// the documented schemes (ARCH-003 §2 table: semver ← purl golang/npm;
// debian ← purl deb; rpm ← purl rpm; maven ← purl maven). Types without a
// documented mapping (pypi, gem, oci, docker, generic, …) intentionally
// yield no hint — inference falls through to CPE/shape instead of guessing
// an ordering the domain does not implement. Extending this map is the
// single point of change when a new ecosystem mapping is agreed.
var purlSchemeHints = map[string]domain.VersionScheme{
	"golang": domain.VersionSchemeSemver,
	"npm":    domain.VersionSchemeSemver,
	"deb":    domain.VersionSchemeDebian,
	"rpm":    domain.VersionSchemeRPM,
	"maven":  domain.VersionSchemeMaven,
}

// PURLSchemeHint maps one purl type onto the ordering scheme documented
// for it (ARCH-003 §2 item 4: the purl type is the primary hint). ok is
// false for types without a documented mapping.
func PURLSchemeHint(purlType string) (domain.VersionScheme, bool) {
	hint, ok := purlSchemeHints[purlType]
	return hint, ok
}

// cpeOSDebianVendors are operating-system CPE vendors whose packages order
// with dpkg semantics (Debian and its direct derivatives; canonical is
// Ubuntu). Matched against the lowercased CPE vendor of part "o".
var cpeOSDebianVendors = map[string]bool{
	"debian": true, "canonical": true,
}

// cpeOSRPMVendors are operating-system CPE vendors whose packages order
// with RPM EVR semantics (RHEL and its derivatives/alikes, SUSE, Amazon
// Linux, Oracle Linux). Matched against the lowercased CPE vendor of part
// "o".
var cpeOSRPMVendors = map[string]bool{
	"redhat": true, "centos": true, "fedora": true,
	"almalinux": true, "rockylinux": true,
	"suse": true, "opensuse": true,
	"amazon": true, "oracle": true,
}

// cpeSchemeHint extracts a scheme hint from a decomposed CPE. Only the
// operating-system part (part "o") carries a reliable family signal — the
// package manager of the OS is known from the vendor; an application CPE
// (part "a") does not say which ordering its version follows (a product
// could be a Go module, an npm package or a native binary), so no hint is
// fabricated. ok is false when the CPE yields no hint. CPE values are
// case-insensitive by spec; the vendor is compared lowercased.
func cpeSchemeHint(c CPE23) (domain.VersionScheme, bool) {
	if c.Part != "o" {
		return "", false
	}
	vendor := strings.ToLower(c.Vendor)
	if cpeOSDebianVendors[vendor] {
		return domain.VersionSchemeDebian, true
	}
	if cpeOSRPMVendors[vendor] {
		return domain.VersionSchemeRPM, true
	}
	return "", false
}

// isCalverShape reports whether version has the calendar-version shape
// that infers VersionSchemeCalver: YYYY, YYYY.MM or YYYY.MM.DD ('.' or
// '-' separated), or the compact YYYYMMDD, with a four-digit year and an
// in-range month/day where present. The acceptance mirrors the domain's
// calver parser (parseCalver in internal/domain/version_strategy.go —
// DEV-044) exactly, so an inferred calver is always orderable by
// CompareCalver and the two can never disagree about a version.
func isCalverShape(version string) bool {
	if version == "" {
		return false
	}
	if len(version) == 8 && isAllASCIIDigits(version) {
		return calverPartsValid(version[:4], version[4:6], version[6:8])
	}
	if !isAllASCIIDigits(version) && !digitsSeparatedOnly(version) {
		return false
	}
	parts := strings.FieldsFunc(version, func(r rune) bool { return r == '.' || r == '-' })
	if len(parts) < 1 || len(parts) > 3 {
		return false
	}
	month, day := "", ""
	if len(parts) > 1 {
		month = parts[1]
	}
	if len(parts) > 2 {
		day = parts[2]
	}
	return calverPartsValid(parts[0], month, day)
}

// calverPartsValid validates the year/month/day digit parts (month and day
// optional): a four-digit year and a month/day inside 1–12 / 1–31,
// mirroring the domain calver parser (calverFromParts / parseSmallDigits).
func calverPartsValid(year, month, day string) bool {
	if len(year) != 4 || !isAllASCIIDigits(year) {
		return false
	}
	if month != "" && !smallDigitsInRange(month, 12) {
		return false
	}
	if day != "" && !smallDigitsInRange(day, 31) {
		return false
	}
	return true
}

// smallDigitsInRange mirrors the domain calver parser's parseSmallDigits:
// a 1-2 digit number in [1, max]; leading zeros are accepted ("01" == "1").
func smallDigitsInRange(s string, max int) bool {
	if s == "" || len(s) > 2 || !isAllASCIIDigits(s) {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n >= 1 && n <= max
}

// digitsSeparatedOnly reports whether s contains only ASCII digits, dots
// and dashes and at least one digit (mirrors the domain calver parser's
// allDigitsSeparated; pure-digit strings skip this check there).
func digitsSeparatedOnly(s string) bool {
	digits := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits = true
		case c == '.' || c == '-':
		default:
			return false
		}
	}
	return digits
}

// isAllASCIIDigits reports whether s is non-empty and all ASCII digits.
func isAllASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
