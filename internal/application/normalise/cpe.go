package normalise

import "strings"

// This file implements the CPE 2.3 formatted-string decomposition of
// ARCH-003 §2 item 3: validate and decompose
//
//	cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//
// into vendor/product/version/update (the full 11-attribute struct is kept
// so the decomposition round-trips exactly and the NVD-side criteria can be
// compared field for field). A malformed CPE is a positioned *SyntaxError
// (validate/quarantine error, never a silent default, ARCH-003 §2 item 3).
//
// Grammar notes:
//
//   - The formatted string is the 13-colon-separated binding of NISTIR
//     7695: the literal "cpe:2.3:" prefix plus 11 attributes. The whole
//     binding is case-insensitive by spec, but the values are preserved
//     verbatim here — case folding is the comparison-key concern of the
//     caller (the natural-key derivation of internal/domain/naturalkey.go
//     already lowercases the whole CPE), and decomposition must not
//     reshape an original that the database stores verbatim.
//   - "*" (ANY) and "-" (NA) are valid attribute values in every
//     position and are returned verbatim; they are not folded into empty
//     strings, so a consumer can tell "any version" from "no version".
//   - Backslash escaping is a WFN (structured) binding concern; the
//     formatted binding stores readable values and a value containing an
//     unescaped ':' is structurally impossible (it would change the field
//     count and is rejected as such).

// cpe23AttributeCount is the number of attributes after the "cpe:2.3:"
// prefix (NISTIR 7695: part through other = 11), giving 13 colon-separated
// fields in total.
const cpe23AttributeCount = 11

// cpe23FieldNames names the 11 attributes by their position (1-based, the
// machine positions of *SyntaxError).
var cpe23FieldNames = [cpe23AttributeCount]string{
	"part", "vendor", "product", "version", "update",
	"edition", "language", "sw_edition", "target_sw", "target_hw", "other",
}

// cpe23PartAny are the three allowed part values of CPE 2.3.
var cpe23Parts = map[string]bool{"a": true, "h": true, "o": true}

// CPE23 is a decomposed CPE 2.3 formatted string (ARCH-003 §2 item 3).
// The 11 attributes are stored verbatim, in spec order; Vendor/Product/
// Version/Update are the fields the matching semantics read, the remaining
// seven (Edition through Other) are kept so String round-trips exactly and
// a full criteria comparison stays possible.
type CPE23 struct {
	Part    string // a (application) | h (hardware) | o (operating system)
	Vendor  string // "*" / "-" allowed, returned verbatim
	Product string
	Version string
	Update  string
	Edition string
	// Language of the CPE 2.3 formatted string (position 7); note the
	// spec's position 6 is the "language" attribute of the deprecated
	// binding — the formatted string keeps the 2.3 ordering.
	Language  string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
}

// ParseCPE23 decomposes one CPE 2.3 formatted string. It accepts exactly
// the 13-field binding: the literal lowercase "cpe" and "2.3" markers, a
// part of a/h/o and eleven non-empty attributes (any of which may be the
// "*" or "-" wildcards). Anything else — wrong field count, wrong prefix,
// an unknown part, an empty attribute, control characters — is a
// positioned *SyntaxError.
func ParseCPE23(input string) (CPE23, error) {
	if input == "" {
		return CPE23{}, wholeInputError("cpe", input, "empty CPE string")
	}
	fields := strings.Split(input, ":")
	if len(fields) != cpe23AttributeCount+2 {
		return CPE23{}, wholeInputError("cpe", input, "CPE 2.3 requires 13 colon-separated fields (cpe:2.3 plus 11 attributes)")
	}
	if fields[0] != "cpe" {
		return CPE23{}, wholeInputError("cpe", input, "must start with the literal \"cpe:2.3:\" prefix")
	}
	if fields[1] != "2.3" {
		return CPE23{}, wholeInputError("cpe", input, "must use the 2.3 binding (\"cpe:2.3:...\")")
	}
	c := CPE23{}
	attrs := [cpe23AttributeCount]*string{
		&c.Part, &c.Vendor, &c.Product, &c.Version, &c.Update,
		&c.Edition, &c.Language, &c.SWEdition, &c.TargetSW, &c.TargetHW, &c.Other,
	}
	for i, dst := range attrs {
		value := fields[i+2]
		if value == "" {
			return CPE23{}, syntaxError("cpe", cpe23FieldNames[i], i+1, input, "attribute must not be empty")
		}
		if hasControlChar(value) {
			return CPE23{}, syntaxError("cpe", cpe23FieldNames[i], i+1, input, "attribute contains control characters")
		}
		*dst = value
	}
	if !cpe23Parts[c.Part] {
		return CPE23{}, syntaxError("cpe", "part", 1, input, "part must be \"a\", \"h\" or \"o\"")
	}
	return c, nil
}

// String reassembles the decomposed attributes into the canonical
// 13-field formatted string. For every string ParseCPE23 accepts,
// Parse(s).String() == s — the decomposition never reshapes an original.
func (c CPE23) String() string {
	return "cpe:2.3:" + strings.Join([]string{
		c.Part, c.Vendor, c.Product, c.Version, c.Update,
		c.Edition, c.Language, c.SWEdition, c.TargetSW, c.TargetHW, c.Other,
	}, ":")
}
