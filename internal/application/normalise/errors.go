package normalise

import "fmt"

// SyntaxError is a positioned parse failure of one identifier string
// (CPE 2.3, purl or image reference, ARCH-003 §2 items 3-5). It reports
// the offending attribute and its position in the decomposition so a
// validate pass can surface it as a position/reason pair (ARCH-003 §1.3:
// "Every failure is positioned (line, column) and reported like a
// quarantine position/reason pair"). A parser never returns a partial
// struct or a silent default — an invalid identifier is always a
// *SyntaxError.
type SyntaxError struct {
	// Kind is the identifier grammar: "cpe" | "purl" | "image".
	Kind string
	// Field is the offending attribute name (e.g. "vendor", "type",
	// "digest"); "" when the whole string fails (bad prefix, wrong
	// field count, empty input).
	Field string
	// Index is the 1-based attribute position in the ordered
	// decomposition; 0 when the whole string fails. It is the
	// machine-readable half of the position/reason pair.
	Index int
	// Reason is the human-readable half of the pair.
	Reason string
	// Input is the offending string, verbatim.
	Input string
}

// Error renders the positioned failure; it always mentions the input so a
// log line or validate report stays self-contained.
func (e *SyntaxError) Error() string {
	if e.Field == "" || e.Index == 0 {
		return fmt.Sprintf("normalise: %s: %s in %q", e.Kind, e.Reason, e.Input)
	}
	return fmt.Sprintf("normalise: %s: attribute %d (%s): %s in %q", e.Kind, e.Index, e.Field, e.Reason, e.Input)
}

// syntaxError assembles a positioned *SyntaxError.
func syntaxError(kind, field string, index int, input, reason string) *SyntaxError {
	return &SyntaxError{Kind: kind, Field: field, Index: index, Reason: reason, Input: input}
}

// wholeInputError is the whole-string variant (bad prefix, empty input,
// wrong field count): no attribute position exists yet.
func wholeInputError(kind, input, reason string) *SyntaxError {
	return syntaxError(kind, "", 0, input, reason)
}

// hasControlChar reports whether s contains a control character (the
// parsers reject control bytes anywhere — they cannot appear in any of the
// grammars, even percent-encoded forms use printable hex).
func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
