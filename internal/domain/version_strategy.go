package domain

import (
	"fmt"
	"strings"
)

// This file implements the pure version semantics of ARCH-003 §2 ("Version
// semantics — no lexicographic compare", ch. 9.1, TRI-02). Every strategy
// returns an ordering (less/equal/greater) for two versions of its scheme
// and evaluates an NVD-style version range. All functions are pure,
// deterministic and network-free; none of them ever falls back to a plain
// lexicographic string compare.
//
// unknown is the one scheme with no ordering: Compare errors instead of
// fabricating an order (ARCH-003 §2: "unknown is not an error but demotes
// the match … it never fabricates an ordering").

// Ordering is the result of comparing two versions (less/equal/greater).
type Ordering int

// Allowed Ordering values. The numeric values match the convention of
// strings.Compare so results can flow into sort interfaces unchanged.
const (
	OrderingLess    Ordering = -1
	OrderingEqual   Ordering = 0
	OrderingGreater Ordering = 1
)

// String renders the ordering as "<", "=" or ">".
func (o Ordering) String() string {
	switch o {
	case OrderingLess:
		return "<"
	case OrderingGreater:
		return ">"
	default:
		return "="
	}
}

// VersionStrategy orders versions of one VersionScheme (ARCH-003 §2). A
// strategy per scheme returns less/equal/greater for two versions of the
// scheme; the range semantics (Contains) builds on Compare. Versions are
// expected normalised (trimmed); an empty version is never orderable —
// a missing version has no ordering in any scheme. Obtain strategies with
// StrategyFor; every scheme has exactly one stateless strategy.
type VersionStrategy interface {
	// Scheme is the scheme this strategy orders.
	Scheme() VersionScheme
	// Compare orders a against b: OrderingLess when a < b, OrderingEqual
	// when equal, OrderingGreater when a > b. It errors on empty versions
	// and on versions the scheme cannot parse — never fabricates an order.
	Compare(a, b string) (Ordering, error)
	// Contains evaluates an NVD-style version range (versionStart/End with
	// including/excluding semantics) against one version of the scheme.
	Contains(version string, rng VersionRange) (bool, error)
}

// VersionRange is the NVD configuration version window of ARCH-003 §3 /
// §2 (the NVD fields versionStartIncluding/versionStartExcluding and
// versionEndIncluding/versionEndExcluding map onto it): a lower bound
// Start, an upper bound End, each with an including flag. An empty bound
// string is an open bound; a range with no bounds covers every version.
//
//	Start=""                 → no lower bound
//	Start="1.0",  Including  → version >= 1.0        (versionStartIncluding)
//	Start="1.0",  Excluding  → version >  1.0        (versionStartExcluding)
//	End="2.0",    Including  → version <= 2.0        (versionEndIncluding)
//	End="2.0",    Excluding  → version <  2.0        (versionEndExcluding)
type VersionRange struct {
	Start          string // lower bound; "" = open
	StartIncluding bool   // true: version >= Start; false: version > Start
	End            string // upper bound; "" = open
	EndIncluding   bool   // true: version <= End; false: version < End
}

// versionStrategy is the stateless implementation shared by every concrete
// scheme: it delegates Compare to the scheme's pure comparator function.
type versionStrategy struct {
	scheme  VersionScheme
	compare func(a, b string) (Ordering, error)
}

func (s versionStrategy) Scheme() VersionScheme { return s.scheme }

func (s versionStrategy) Compare(a, b string) (Ordering, error) { return s.compare(a, b) }

func (s versionStrategy) Contains(version string, rng VersionRange) (bool, error) {
	return inVersionRange(version, rng, s)
}

// unknownVersionStrategy is the strategy of VersionSchemeUnknown: versions
// with an unknown scheme have no ordering, so every comparison and every
// bounded range evaluation errors instead of fabricating a result.
type unknownVersionStrategy struct{}

func (unknownVersionStrategy) Scheme() VersionScheme { return VersionSchemeUnknown }

func (unknownVersionStrategy) Compare(string, string) (Ordering, error) {
	return OrderingEqual, fmt.Errorf("domain: version scheme unknown: versions cannot be ordered")
}

func (unknownVersionStrategy) Contains(version string, rng VersionRange) (bool, error) {
	return inVersionRange(version, rng, unknownVersionStrategy{})
}

// versionStrategies is the registry behind StrategyFor. Every allowed
// scheme maps to exactly one stateless strategy.
var versionStrategies = map[VersionScheme]VersionStrategy{
	VersionSchemeSemver:  versionStrategy{VersionSchemeSemver, CompareSemver},
	VersionSchemeDebian:  versionStrategy{VersionSchemeDebian, CompareDebian},
	VersionSchemeRPM:     versionStrategy{VersionSchemeRPM, CompareRPM},
	VersionSchemeMaven:   versionStrategy{VersionSchemeMaven, CompareMaven},
	VersionSchemeCalver:  versionStrategy{VersionSchemeCalver, CompareCalver},
	VersionSchemeGeneric: versionStrategy{VersionSchemeGeneric, CompareGeneric},
}

// StrategyFor returns the VersionStrategy of a scheme. An unknown or
// invalid scheme yields the unknown strategy — never nil — whose Compare
// and bounded Contains error (no ordering is ever fabricated).
func StrategyFor(scheme VersionScheme) VersionStrategy {
	if s, ok := versionStrategies[scheme]; ok {
		return s
	}
	return unknownVersionStrategy{}
}

// InRange is the NVD range evaluator (ARCH-003 §2/§3): it reports whether
// version lies inside rng under the ordering of strategy. Both bounds are
// optional; an unbounded range contains every (non-empty) version. A range
// with a bound over a scheme that cannot order (unknown) errors. An empty
// version is never "in range" — a missing version cannot be proven inside
// any window (the matcher demotes such a component instead).
func InRange(version string, rng VersionRange, strategy VersionStrategy) (bool, error) {
	return inVersionRange(version, rng, strategy)
}

func inVersionRange(version string, rng VersionRange, strategy VersionStrategy) (bool, error) {
	if strings.TrimSpace(version) == "" {
		return false, fmt.Errorf("domain: version range: cannot evaluate an empty version")
	}
	if rng.Start == "" && rng.End == "" {
		return true, nil // unbounded window
	}
	if rng.Start != "" {
		res, err := strategy.Compare(version, rng.Start)
		if err != nil {
			return false, fmt.Errorf("domain: version range: start bound %q: %w", rng.Start, err)
		}
		if rng.StartIncluding {
			if res == OrderingLess {
				return false, nil
			}
		} else if res != OrderingGreater {
			return false, nil
		}
	}
	if rng.End != "" {
		res, err := strategy.Compare(version, rng.End)
		if err != nil {
			return false, fmt.Errorf("domain: version range: end bound %q: %w", rng.End, err)
		}
		if rng.EndIncluding {
			if res == OrderingGreater {
				return false, nil
			}
		} else if res != OrderingLess {
			return false, nil
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Shared numeric helpers
// ---------------------------------------------------------------------------

// compareDigitStrings compares two non-empty ASCII digit strings by their
// numeric value (leading zeros are ignored; no width overflow).
func compareDigitStrings(a, b string) Ordering {
	aa := strings.TrimLeft(a, "0")
	bb := strings.TrimLeft(b, "0")
	if aa == "" {
		aa = "0"
	}
	if bb == "" {
		bb = "0"
	}
	switch {
	case len(aa) < len(bb):
		return OrderingLess
	case len(aa) > len(bb):
		return OrderingGreater
	case aa < bb:
		return OrderingLess
	case aa > bb:
		return OrderingGreater
	}
	return OrderingEqual
}

// isDigits reports whether s is non-empty and contains only ASCII digits.
func isDigits(s string) bool {
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

// isASCIIDigitByte reports whether b is an ASCII digit.
func isASCIIDigitByte(b byte) bool { return b >= '0' && b <= '9' }

// orderFromSign converts a strings.Compare-style sign into an Ordering.
func orderFromSign(sign int) Ordering {
	switch {
	case sign < 0:
		return OrderingLess
	case sign > 0:
		return OrderingGreater
	}
	return OrderingEqual
}

// ---------------------------------------------------------------------------
// semver — MAJOR.MINOR.PATCH + pre-release/build rules (semver.org)
// ---------------------------------------------------------------------------

// semverPreID is one dot-separated pre-release identifier: numeric (only
// digits) or alphanumeric (letters and digits).
type semverPreID struct {
	numeric bool
	digits  string // numeric identifier (digits only)
	text    string // alphanumeric identifier (ASCII, case-preserved)
}

// semverVersion is a parsed semver. Missing MINOR/PATCH are coerced to 0
// (the npm-style leniency documented below); build metadata is dropped
// because it never participates in precedence.
type semverVersion struct {
	major, minor, patch string
	pre                 []semverPreID
}

// parseSemver parses a semver with the leniencies commonly applied to
// inventory versions: an optional leading "v"/"V"/"=" prefix (npm style)
// and MAJOR or MAJOR.MINOR in place of the full MAJOR.MINOR.PATCH (missing
// parts coerce to 0 — 1.2 orders equal to 1.2.0). Everything else is
// strict: numeric parts only, pre-release identifiers non-empty and made of
// ASCII letters/digits, build metadata (after "+") ignored.
func parseSemver(s string) (semverVersion, error) {
	if s == "" {
		return semverVersion{}, fmt.Errorf("empty version")
	}
	for len(s) > 0 && (s[0] == 'v' || s[0] == 'V' || s[0] == '=') {
		s = s[1:]
	}
	if s == "" {
		return semverVersion{}, fmt.Errorf("empty version after prefix")
	}
	core := s
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i] // build metadata: no precedence
	}
	var preRaw string
	hasPre := false
	if i := strings.IndexByte(core, '-'); i >= 0 {
		hasPre = true
		preRaw = core[i+1:]
		core = core[:i]
	}
	if hasPre && preRaw == "" {
		return semverVersion{}, fmt.Errorf("empty pre-release in %q", s)
	}
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return semverVersion{}, fmt.Errorf("more than three version parts in %q", core)
	}
	nums := [3]string{"0", "0", "0"}
	for i, p := range parts {
		if !isDigits(p) {
			return semverVersion{}, fmt.Errorf("version part %q is not numeric", p)
		}
		nums[i] = p
	}
	var pre []semverPreID
	if preRaw != "" {
		for _, id := range strings.Split(preRaw, ".") {
			if id == "" {
				return semverVersion{}, fmt.Errorf("empty pre-release identifier in %q", preRaw)
			}
			if isDigits(id) {
				pre = append(pre, semverPreID{numeric: true, digits: id})
				continue
			}
			for i := 0; i < len(id); i++ {
				c := id[i]
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
					return semverVersion{}, fmt.Errorf("pre-release identifier %q contains non-alphanumeric characters", id)
				}
			}
			pre = append(pre, semverPreID{numeric: false, text: id})
		}
	}
	return semverVersion{major: nums[0], minor: nums[1], patch: nums[2], pre: pre}, nil
}

// CompareSemver orders two semver versions by precedence (semver.org §11):
// numeric MAJOR.MINOR.PATCH first, then pre-release identifiers — a
// version with pre-release identifiers is always older than the same
// version without; numeric pre-release identifiers compare numerically and
// sort before alphanumeric ones, which compare in ASCII order; a longer
// pre-release list with an equal prefix is newer. Build metadata never
// participates.
func CompareSemver(a, b string) (Ordering, error) {
	av, err := parseSemver(a)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: semver %q: %w", a, err)
	}
	bv, err := parseSemver(b)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: semver %q: %w", b, err)
	}
	for _, part := range []struct{ x, y string }{{av.major, bv.major}, {av.minor, bv.minor}, {av.patch, bv.patch}} {
		if o := compareDigitStrings(part.x, part.y); o != OrderingEqual {
			return o, nil
		}
	}
	switch {
	case len(av.pre) == 0 && len(bv.pre) == 0:
		return OrderingEqual, nil
	case len(av.pre) == 0:
		return OrderingGreater, nil // release > pre-release
	case len(bv.pre) == 0:
		return OrderingLess, nil
	}
	for i := 0; i < len(av.pre) && i < len(bv.pre); i++ {
		x, y := av.pre[i], bv.pre[i]
		switch {
		case x.numeric && y.numeric:
			if o := compareDigitStrings(x.digits, y.digits); o != OrderingEqual {
				return o, nil
			}
		case x.numeric:
			return OrderingLess, nil // numeric identifiers sort before alphanumeric
		case y.numeric:
			return OrderingGreater, nil
		default:
			if o := orderFromSign(strings.Compare(x.text, y.text)); o != OrderingEqual {
				return o, nil
			}
		}
	}
	// Equal prefix: the longer pre-release list is newer.
	switch {
	case len(av.pre) > len(bv.pre):
		return OrderingGreater, nil
	case len(av.pre) < len(bv.pre):
		return OrderingLess, nil
	}
	return OrderingEqual, nil
}

// ---------------------------------------------------------------------------
// debian — dpkg version compare (deb-version(7)):
// [epoch:]upstream[-revision]
// ---------------------------------------------------------------------------

// debVersion is a parsed dpkg version: an epoch (digit string), the
// upstream part and the revision after the last hyphen ("" when absent).
type debVersion struct {
	epoch    string
	upstream string
	revision string
}

// parseDebian parses a dpkg version string: an optional epoch (digits
// before the first colon, absent epoch is 0), an upstream part (which may
// contain hyphens once a revision exists) and a revision split off at the
// last hyphen. Empty input, an empty upstream, a non-numeric epoch or a
// second colon all error — the parser never silently reshapes a version.
func parseDebian(s string) (debVersion, error) {
	if s == "" {
		return debVersion{}, fmt.Errorf("empty version")
	}
	epoch, rest := "0", s
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		if !isDigits(rest[:i]) {
			return debVersion{}, fmt.Errorf("epoch %q is not numeric", rest[:i])
		}
		epoch = strings.TrimLeft(rest[:i], "0")
		if epoch == "" {
			epoch = "0"
		}
		rest = rest[i+1:]
	}
	if rest == "" {
		return debVersion{}, fmt.Errorf("empty version after epoch")
	}
	if strings.Contains(rest, ":") {
		return debVersion{}, fmt.Errorf("version %q contains more than one colon", s)
	}
	upstream, revision := rest, ""
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		upstream = rest[:i]
		revision = rest[i+1:]
	}
	if upstream == "" {
		return debVersion{}, fmt.Errorf("empty upstream part in %q", s)
	}
	return debVersion{epoch: epoch, upstream: upstream, revision: revision}, nil
}

// CompareDebian orders two versions with the dpkg algorithm of
// deb-version(7): epochs numerically, then the upstream parts, then the
// revisions — each with the dpkg character ordering (dpkgOrderCompare):
// "~" sorts before everything (even the end of the string), letters sort
// before non-letters, and runs of digits compare numerically (leading
// zeros stripped) instead of lexicographically. A missing revision is the
// empty string and sorts before any present revision.
func CompareDebian(a, b string) (Ordering, error) {
	av, err := parseDebian(a)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: debian %q: %w", a, err)
	}
	bv, err := parseDebian(b)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: debian %q: %w", b, err)
	}
	if o := compareDigitStrings(av.epoch, bv.epoch); o != OrderingEqual {
		return o, nil
	}
	if o := dpkgOrderCompare(av.upstream, bv.upstream); o != OrderingEqual {
		return o, nil
	}
	return dpkgOrderCompare(av.revision, bv.revision), nil
}

// dpkgOrder maps one byte of a dpkg version to its comparison order
// (deb-version(7)): '~' before everything (including the end of the
// string), letters by their byte value, every other byte after the
// letters. Versions are ASCII; bytes are compared, mirroring dpkg.
func dpkgOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c == 0: // end of string
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

// dpkgOrderCompare compares two strings with the dpkg verrevcmp character
// algorithm: runs of digits on both sides compare numerically (leading
// zeros stripped, longer run wins); any other position compares single
// bytes by dpkgOrder. It is total over ASCII strings and is also the
// engine of the generic scheme (which applies it to whole strings).
func dpkgOrderCompare(a, b string) Ordering {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isASCIIDigitByte(a[i])) || (j < len(b) && !isASCIIDigitByte(b[j])) {
			ac := dpkgOrder(byteAt(a, i))
			bc := dpkgOrder(byteAt(b, j))
			if ac != bc {
				return orderFromSign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isASCIIDigitByte(a[i]) && j < len(b) && isASCIIDigitByte(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isASCIIDigitByte(a[i]) {
			return OrderingGreater // longer digit run after zero strip wins
		}
		if j < len(b) && isASCIIDigitByte(b[j]) {
			return OrderingLess
		}
		if firstDiff != 0 {
			return orderFromSign(firstDiff)
		}
	}
	return OrderingEqual
}

// byteAt returns s[i], or 0 past the end (the dpkg end-of-string marker).
func byteAt(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

// ---------------------------------------------------------------------------
// rpm — EVR (epoch:version-release), rpmvercmp ordering
// ---------------------------------------------------------------------------

// rpmEVR is a parsed RPM version: an epoch (digits, absent is 0), the
// version and the release split at the first hyphen (release is "" when
// absent — rpm versions never contain hyphens, so the first hyphen is the
// separator).
type rpmEVR struct {
	epoch   string
	version string
	release string
}

func parseRPMEVR(s string) (rpmEVR, error) {
	if s == "" {
		return rpmEVR{}, fmt.Errorf("empty version")
	}
	epoch, rest := "0", s
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		if !isDigits(rest[:i]) {
			return rpmEVR{}, fmt.Errorf("epoch %q is not numeric", rest[:i])
		}
		epoch = strings.TrimLeft(rest[:i], "0")
		if epoch == "" {
			epoch = "0"
		}
		rest = rest[i+1:]
	}
	if rest == "" {
		return rpmEVR{}, fmt.Errorf("empty version after epoch")
	}
	if strings.Contains(rest, ":") {
		return rpmEVR{}, fmt.Errorf("version %q contains more than one colon", s)
	}
	version, release := rest, ""
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		version = rest[:i]
		release = rest[i+1:]
	}
	if version == "" {
		return rpmEVR{}, fmt.Errorf("empty version part in %q", s)
	}
	return rpmEVR{epoch: epoch, version: version, release: release}, nil
}

// CompareRPM orders two versions as RPM EVRs: epochs numerically, then the
// version parts, then the release parts — each through rpmvercmpCompare
// (rpm's rpmvercmp, with "~" sorting before everything and numeric
// segments compared by length then byte order, as rpm does).
func CompareRPM(a, b string) (Ordering, error) {
	av, err := parseRPMEVR(a)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: rpm %q: %w", a, err)
	}
	bv, err := parseRPMEVR(b)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: rpm %q: %w", b, err)
	}
	if o := compareDigitStrings(av.epoch, bv.epoch); o != OrderingEqual {
		return o, nil
	}
	if o := rpmvercmpCompare(av.version, bv.version); o != OrderingEqual {
		return o, nil
	}
	return rpmvercmpCompare(av.release, bv.release), nil
}

// rpmvercmpCompare implements rpm's rpmvercmp semantics: version strings
// are consumed as alternating numeric (digit-run) and alpha (letter-run,
// which absorbs any punctuation up to the next digit) segments; separators
// between segments are ignored; "~" at a segment boundary sorts before
// everything. Numeric segments compare by digit count first and then byte
// order (rpm behaviour — leading zeros are significant), alpha segments
// case-insensitively, and a numeric segment is always newer than an alpha
// segment. All equal up to the end of one string: the longer string is
// newer. It is total over ASCII strings.
func rpmvercmpCompare(a, b string) Ordering {
	if a == b {
		return OrderingEqual
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// '~' sorts before everything, including the start of the other
		// string and its end.
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return OrderingGreater // side a has no '~' here → a is newer
			}
			if j >= len(b) || b[j] != '~' {
				return OrderingLess
			}
			i++
			j++
			continue
		}
		// Skip segment separators (neither digit nor letter).
		for i < len(a) && !isRPMAlphaNum(a[i]) {
			i++
		}
		for j < len(b) && !isRPMAlphaNum(b[j]) {
			j++
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		// Segment boundaries: numeric segments run to the next non-digit,
		// alpha segments run to the next digit (absorbing punctuation).
		segAEnd := i
		if isASCIIDigitByte(a[i]) {
			for segAEnd < len(a) && isASCIIDigitByte(a[segAEnd]) {
				segAEnd++
			}
		} else {
			for segAEnd < len(a) && !isASCIIDigitByte(a[segAEnd]) {
				segAEnd++
			}
		}
		segBEnd := j
		if isASCIIDigitByte(b[j]) {
			for segBEnd < len(b) && isASCIIDigitByte(b[segBEnd]) {
				segBEnd++
			}
		} else {
			for segBEnd < len(b) && !isASCIIDigitByte(b[segBEnd]) {
				segBEnd++
			}
		}
		segA, segB := a[i:segAEnd], b[j:segBEnd]
		digA, digB := isASCIIDigitByte(a[i]), isASCIIDigitByte(b[j])
		switch {
		case digA && digB:
			switch {
			case len(segA) != len(segB):
				if len(segA) < len(segB) {
					return OrderingLess
				}
				return OrderingGreater
			case segA != segB:
				if segA < segB {
					return OrderingLess
				}
				return OrderingGreater
			}
		case digA:
			return OrderingGreater // numeric segments are newer than alpha
		case digB:
			return OrderingLess
		default:
			la, lb := strings.ToLower(segA), strings.ToLower(segB)
			if la != lb {
				if la < lb {
					return OrderingLess
				}
				return OrderingGreater
			}
		}
		i, j = segAEnd, segBEnd
	}
	// One side ran out of segments: the side with remaining content is
	// newer (1.0.1 > 1.0, 1.0a > 1.0 — never the reverse).
	switch {
	case i >= len(a) && j >= len(b):
		return OrderingEqual
	case i >= len(a):
		return OrderingLess
	default:
		return OrderingGreater
	}
}

// isRPMAlphaNum reports whether b is an ASCII letter or digit (the only
// characters rpmvercmp ever compares as segment content).
func isRPMAlphaNum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// ---------------------------------------------------------------------------
// maven — Maven version ordering for the documented core
// ---------------------------------------------------------------------------

// mavenItem is one token of a Maven version. Tokens are numeric (pure
// digits; zero folds into the release position), pre-release qualifiers
// (alpha…snapshot), the release marker (ga/final/release), the sp marker,
// or an unknown qualifier compared as a string.
type mavenItem struct {
	pre  int    // rank of a known pre-release qualifier
	num  string // numeric token with leading zeros trimmed (numeric kind only)
	str  string // unknown qualifier, lowercased (string kind only)
	kind mavenItemKind
}

// mavenItemKind classifies a Maven token. The category order below is the
// documented Maven ComparableVersion core ordering: pre-release qualifiers
// alpha < beta < milestone < rc < snapshot < release (= numeric 0, missing
// tokens pad to release) < numeric builds 1, 2, … < sp < unknown
// qualifiers (compared as strings).
type mavenItemKind int

const (
	mavenItemPre mavenItemKind = iota
	mavenItemRelease
	mavenItemNumeric
	mavenItemSP
	mavenItemString
)

// mavenQualifiers maps the known Maven pre-release qualifiers to their
// rank. ga/final/release are the release marker (handled separately).
var mavenQualifiers = map[string]int{
	"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4,
}

// parseMavenVersion tokenises a Maven version into items: lowercase, split
// on separators ('.', '-' and any other non-alphanumeric) and on
// digit/letter transitions, then classify. Empty tokens are dropped;
// numeric "0" tokens fold into the release position.
func parseMavenVersion(s string) ([]mavenItem, error) {
	if s == "" {
		return nil, fmt.Errorf("empty version")
	}
	lower := strings.ToLower(s)
	var items []mavenItem
	i := 0
	for i < len(lower) {
		c := lower[i]
		if !isRPMAlphaNum(c) { // separator
			i++
			continue
		}
		if isASCIIDigitByte(c) {
			start := i
			for i < len(lower) && isASCIIDigitByte(lower[i]) {
				i++
			}
			num := strings.TrimLeft(lower[start:i], "0")
			if num == "" {
				items = append(items, mavenItem{kind: mavenItemRelease})
			} else {
				items = append(items, mavenItem{kind: mavenItemNumeric, num: num})
			}
			continue
		}
		start := i
		for i < len(lower) && lower[i] >= 'a' && lower[i] <= 'z' {
			i++
		}
		word := lower[start:i]
		switch word {
		case "ga", "final", "release":
			items = append(items, mavenItem{kind: mavenItemRelease})
		case "sp":
			items = append(items, mavenItem{kind: mavenItemSP})
		default:
			if rank, ok := mavenQualifiers[word]; ok {
				items = append(items, mavenItem{kind: mavenItemPre, pre: rank})
			} else {
				items = append(items, mavenItem{kind: mavenItemString, str: word})
			}
		}
	}
	return items, nil
}

func compareMavenItems(x, y mavenItem) Ordering {
	switch {
	case x.kind == mavenItemPre && y.kind == mavenItemPre:
		return orderFromSign(x.pre - y.pre)
	case x.kind == mavenItemNumeric && y.kind == mavenItemNumeric:
		return compareDigitStrings(x.num, y.num)
	case x.kind == mavenItemString && y.kind == mavenItemString:
		return orderFromSign(strings.Compare(x.str, y.str))
	default:
		if x.kind < y.kind {
			return OrderingLess
		}
		if x.kind > y.kind {
			return OrderingGreater
		}
	}
	return OrderingEqual
}

// mavenReleasePad is the padding item a shorter version list compares
// against: a missing token is a release, so 1.0-alpha < 1.0 (release) and
// 1.0 == 1.0.0 (numeric zero folded into release) both hold.
var mavenReleasePad = mavenItem{kind: mavenItemRelease}

// CompareMaven orders two Maven versions with the documented Comparable-
// Version core semantics: position-wise token comparison where missing
// tokens count as the release, numeric tokens compare numerically, and the
// category order is alpha < beta < milestone < rc < snapshot < release
// < numeric builds < sp < unknown qualifiers (which compare as lowercased
// strings). The canonical chain
// 1.0-alpha-1 < … < 1.0-snapshot-1 < 1.0 < 1.0-1 < 1.0-sp-1 holds.
func CompareMaven(a, b string) (Ordering, error) {
	av, err := parseMavenVersion(a)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: maven %q: %w", a, err)
	}
	bv, err := parseMavenVersion(b)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: maven %q: %w", b, err)
	}
	n := len(av)
	if len(bv) > n {
		n = len(bv)
	}
	for i := 0; i < n; i++ {
		x, y := mavenReleasePad, mavenReleasePad
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if o := compareMavenItems(x, y); o != OrderingEqual {
			return o, nil
		}
	}
	return OrderingEqual, nil
}

// ---------------------------------------------------------------------------
// calver — YYYY.MM.DD / YYYYMMDD (and the shorter YYYY / YYYY.MM forms)
// ---------------------------------------------------------------------------

// calverVersion is a parsed calendar version: year plus optional month and
// day (0 when absent — a year-only or year-month version sorts before the
// dated versions of the same prefix).
type calverVersion struct {
	year, month, day int
}

// parseCalver parses YYYY[.MM[.DD]] (dot or dash separated) or the
// compact YYYYMMDD form. The year must be four digits; an explicit month
// must be 1–12 and an explicit day 1–31; more than three parts error.
func parseCalver(s string) (calverVersion, error) {
	if s == "" {
		return calverVersion{}, fmt.Errorf("empty version")
	}
	if len(s) == 8 && isDigits(s) {
		return calverFromParts(s[:4], s[4:6], s[6:8])
	}
	if !isDigits(s) {
		// Dotted/dashed forms only — anything else is not a calver.
		if !allDigitsSeparated(s) {
			return calverVersion{}, fmt.Errorf("not a calver shape")
		}
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
	if len(parts) < 1 || len(parts) > 3 {
		return calverVersion{}, fmt.Errorf("calver must have 1 to 3 parts, got %d", len(parts))
	}
	month, day := "", ""
	if len(parts) > 1 {
		month = parts[1]
	}
	if len(parts) > 2 {
		day = parts[2]
	}
	return calverFromParts(parts[0], month, day)
}

// calverFromParts validates the year/month/day digit parts (month and day
// may be absent) and assembles a calverVersion.
func calverFromParts(year, month, day string) (calverVersion, error) {
	if len(year) != 4 || !isDigits(year) {
		return calverVersion{}, fmt.Errorf("calver year %q must be four digits", year)
	}
	v := calverVersion{}
	for i := 0; i < 4; i++ {
		v.year = v.year*10 + int(year[i]-'0')
	}
	if month != "" {
		m, ok := parseSmallDigits(month, 12)
		if !ok {
			return calverVersion{}, fmt.Errorf("calver month %q out of range 1-12", month)
		}
		v.month = m
	}
	if day != "" {
		d, ok := parseSmallDigits(day, 31)
		if !ok {
			return calverVersion{}, fmt.Errorf("calver day %q out of range 1-31", day)
		}
		v.day = d
	}
	return v, nil
}

// allDigitsSeparated reports whether s contains only digits, dots and
// dashes and at least one digit (pure-digit strings fall through to the
// compact check).
func allDigitsSeparated(s string) bool {
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

// parseSmallDigits parses a 1-2 digit bound in [1, max]; leading zeros are
// accepted ("01" == "1"). ok is false for out-of-range or malformed input.
func parseSmallDigits(s string, max int) (int, bool) {
	if s == "" || len(s) > 2 || !isDigits(s) {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	if n < 1 || n > max {
		return 0, false
	}
	return n, true
}

// CompareCalver orders two calendar versions numerically by year, month
// and day; an absent month/day compares as 0, so 2024 < 2024.1
// < 2024.1.5 and the compact YYYYMMDD form orders equal to its dotted
// spelling.
func CompareCalver(a, b string) (Ordering, error) {
	av, err := parseCalver(a)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: calver %q: %w", a, err)
	}
	bv, err := parseCalver(b)
	if err != nil {
		return OrderingEqual, fmt.Errorf("domain: calver %q: %w", b, err)
	}
	for _, pair := range []struct{ x, y int }{{av.year, bv.year}, {av.month, bv.month}, {av.day, bv.day}} {
		switch {
		case pair.x < pair.y:
			return OrderingLess, nil
		case pair.x > pair.y:
			return OrderingGreater, nil
		}
	}
	return OrderingEqual, nil
}

// ---------------------------------------------------------------------------
// generic — component-wise numeric segments (dpkg-style byte order)
// ---------------------------------------------------------------------------

// CompareGeneric is the fallback comparator (ARCH-003 §2: "generic —
// component-wise numeric segments, fallback"). It applies the dpkg
// character ordering to the whole string: runs of digits compare
// numerically (leading zeros stripped), "~" sorts before everything,
// letters sort before non-letters, and the end of a string sorts after
// "~" but before any remaining content — so 1.2 < 1.10, 1.0~rc1 < 1.0 and
// 1.0 < 1.0a all hold. It is total over non-empty strings (only empty
// versions error, like every scheme: a missing version has no ordering).
func CompareGeneric(a, b string) (Ordering, error) {
	if strings.TrimSpace(a) == "" {
		return OrderingEqual, fmt.Errorf("domain: generic: empty version")
	}
	if strings.TrimSpace(b) == "" {
		return OrderingEqual, fmt.Errorf("domain: generic: empty version")
	}
	return dpkgOrderCompare(a, b), nil
}
