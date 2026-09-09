package normalise

import "strings"

// This file implements the purl (package URL) decomposition of ARCH-003 §2
// item 4: validate
//
//	pkg:type/namespace/name@version?qualifiers#subpath
//
// and decompose it into namespace/name/version (the purl type is the
// primary hint for version_scheme — see PURLSchemeHint in inference.go;
// namespace/name/version only carry identity here). A malformed purl is a
// positioned *SyntaxError, never a silent default.
//
// Grammar notes (package-url spec, https://github.com/package-url/purl-spec):
//
//   - The literal "pkg:" scheme prefix and a non-empty lowercase type are
//     required; type is a lowercase ASCII letter followed by lowercase
//     ASCII letters/digits and '.', '+', '-'.
//   - name is required and is the last '/'-separated segment of the path
//     after the type; namespace is the (optional) '/'‑joined prefix of
//     that path and may itself contain '/'. No path segment may be empty.
//   - version (after '@'), qualifiers (after '?', an '&'-joined list of
//     key=value pairs) and subpath (after '#') are optional but never
//     empty when their delimiter is present.
//   - namespace/name are case-sensitive per ecosystem and are preserved
//     verbatim (internal/domain/naturalkey.go folds purl for the natural
//     key with trim only for the same reason); the type is compared and
//     validated as-is and must already be lowercase.
//   - Raw content must be printable ASCII without whitespace, and a '%'
//     must start a valid two-hex-digit percent-escape. Anything else must
//     be percent-encoded by the producer; the parser rejects it instead
//     of guessing. Values are kept encoded (no decoding): decomposition
//     must not reshape an original that the database stores verbatim.

// purlSchemePrefix is the literal scheme of every package URL.
const purlSchemePrefix = "pkg:"

// PURL is a decomposed package URL (ARCH-003 §2 item 4). All fields are
// stored verbatim (still percent-encoded when the input encoded them);
// empty string means the part is absent. Qualifiers keeps the raw
// "key=value&…" text without the leading '?'; Subpath keeps the raw path
// without the leading '#'.
type PURL struct {
	Type       string // required, lowercase (the version-scheme hint source)
	Namespace  string // "" when the purl has no namespace segment
	Name       string // required
	Version    string // "" when absent
	Qualifiers string // raw "k=v&k2=v2", "" when absent
	Subpath    string // raw, "" when absent
}

// ParsePURL decomposes one package URL. It requires the literal lowercase
// "pkg:" prefix, a valid lowercase type, a non-empty name and — whenever
// their delimiter is present — a non-empty version, qualifiers and
// subpath. Anything else is a positioned *SyntaxError.
func ParsePURL(input string) (PURL, error) {
	if input == "" {
		return PURL{}, wholeInputError("purl", input, "empty purl string")
	}
	if !strings.HasPrefix(input, purlSchemePrefix) {
		return PURL{}, wholeInputError("purl", input, "must start with the literal \"pkg:\" scheme prefix")
	}
	rest := input[len(purlSchemePrefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return PURL{}, syntaxError("purl", "type", 0, input, "missing '/' after the type — a purl is pkg:type/namespace/name@version")
	}
	typ := rest[:slash]
	if !validPURLType(typ) {
		return PURL{}, syntaxError("purl", "type", 0, input, "type must be a lowercase ASCII letter followed by lowercase ASCII letters/digits, '.', '+' or '-'")
	}
	rest = rest[slash+1:]
	if rest == "" {
		return PURL{}, syntaxError("purl", "name", 0, input, "missing name after the type")
	}

	p := PURL{Type: typ}

	// Split the path (namespace/name) from the optional @version,
	// ?qualifiers and #subpath at the first delimiter.
	path := rest
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		path = rest[:i]
		if err := splitPURLTail(rest[i:], &p, input); err != nil {
			return PURL{}, err
		}
	}
	// Decompose the path: name is the last segment, namespace the rest.
	segs := strings.Split(path, "/")
	name := segs[len(segs)-1]
	if name == "" {
		return PURL{}, syntaxError("purl", "name", 0, input, "name must not be empty")
	}
	if len(segs) > 1 {
		for _, seg := range segs[:len(segs)-1] {
			if seg == "" {
				return PURL{}, syntaxError("purl", "namespace", 0, input, "namespace must not contain an empty segment")
			}
		}
		p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	}
	p.Name = name

	// Content checks: no whitespace/control, valid percent-escapes.
	if err := checkPURLContent(p.Name, "name", 0, input); err != nil {
		return PURL{}, err
	}
	if err := checkPURLContent(p.Namespace, "namespace", 0, input); err != nil {
		return PURL{}, err
	}
	if err := checkPURLContent(p.Version, "version", 0, input); err != nil {
		return PURL{}, err
	}
	if err := checkPURLContent(p.Subpath, "subpath", 0, input); err != nil {
		return PURL{}, err
	}
	if err := checkPURLQualifiers(p.Qualifiers, input); err != nil {
		return PURL{}, err
	}
	return p, nil
}

// splitPURLTail consumes the optional "@version", "?qualifiers" and
// "#subpath" suffix of a purl (tail starts at the first of the three
// delimiters). Fields are non-empty whenever their delimiter is present;
// the canonical order @ → ? → # is not enforced — each delimiter is
// consumed once, in order of appearance, so a stray later '@' inside
// qualifier content stays content (content validation rejects whitespace
// and bad escapes only; strict qualifier grammar is the producer's job).
func splitPURLTail(tail string, p *PURL, input string) error {
	for len(tail) > 0 {
		switch tail[0] {
		case '@':
			version, rest := cutPURLField(tail[1:], "?#")
			if version == "" {
				return syntaxError("purl", "version", 0, input, "version after '@' must not be empty")
			}
			p.Version = version
			tail = rest
		case '?':
			qualifiers, rest := cutPURLField(tail[1:], "#")
			if qualifiers == "" {
				return syntaxError("purl", "qualifiers", 0, input, "qualifiers after '?' must not be empty")
			}
			p.Qualifiers = qualifiers
			tail = rest
		case '#':
			if tail[1:] == "" {
				return syntaxError("purl", "subpath", 0, input, "subpath after '#' must not be empty")
			}
			p.Subpath = tail[1:]
			tail = ""
		}
	}
	return nil
}

// cutPURLField reads one purl field up to the first byte of stops; it
// returns the field and the unconsumed tail ("" when the field ran to the
// end of the input).
func cutPURLField(s, stops string) (field, tail string) {
	if i := strings.IndexAny(s, stops); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// validPURLType reports whether t is a valid lowercase purl type.
func validPURLType(t string) bool {
	if t == "" || !isLowerASCIILetter(t[0]) {
		return false
	}
	for i := 1; i < len(t); i++ {
		c := t[i]
		if !isLowerASCIILetter(c) && !isASCIIDigit(c) && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// checkPURLContent rejects whitespace, control characters and malformed
// percent-escapes in one purl field. index is the attribute position for
// the error (0: the parsers report the offending field textually).
func checkPURLContent(s, field string, index int, input string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x7f {
			return syntaxError("purl", field, index, input, "field contains whitespace or control characters (percent-encode them)")
		}
		if c == '%' {
			if i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2]) {
				return syntaxError("purl", field, index, input, "field contains a malformed percent-escape")
			}
			i += 2
		}
	}
	return nil
}

// checkPURLQualifiers validates the "k=v&k2=v2" shape of the raw
// qualifiers text: at least one pair, each pair with a non-empty key and a
// '=' separator, content without whitespace or bad escapes.
func checkPURLQualifiers(q, input string) error {
	if q == "" {
		return nil
	}
	if err := checkPURLContent(q, "qualifiers", 0, input); err != nil {
		return err
	}
	for _, pair := range strings.Split(q, "&") {
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			return syntaxError("purl", "qualifiers", 0, input, "qualifiers must be '&'-joined key=value pairs with non-empty keys")
		}
		if err := checkPURLContent(pair[eq+1:], "qualifiers", 0, input); err != nil {
			return err
		}
	}
	return nil
}

// String reassembles the decomposed purl. For every string ParsePURL
// accepts, Parse(s).String() == s — the decomposition never reshapes an
// original (no decoding, no case folding, qualifier order preserved).
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString(purlSchemePrefix)
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		b.WriteString(p.Namespace)
		b.WriteByte('/')
	}
	b.WriteString(p.Name)
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(p.Version)
	}
	if p.Qualifiers != "" {
		b.WriteByte('?')
		b.WriteString(p.Qualifiers)
	}
	if p.Subpath != "" {
		b.WriteByte('#')
		b.WriteString(p.Subpath)
	}
	return b.String()
}

// isLowerASCIILetter reports whether b is a lowercase ASCII letter.
func isLowerASCIILetter(b byte) bool { return b >= 'a' && b <= 'z' }

// isASCIIDigit reports whether b is an ASCII digit.
func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// isHexDigit reports whether b is an ASCII hex digit.
func isHexDigit(b byte) bool {
	return isASCIIDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
