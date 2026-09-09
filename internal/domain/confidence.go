package domain

import "fmt"

// Confidence expresses how reliable a vulnerability-to-component assignment
// is (ch. 6.2). It is derived from the authoritative MatchMethod through the
// versioned ADR-015 mapping (mapping.go) and is never stored independently.
// The ch. 9.3 priority rules read exactly this value.
type Confidence string

// Allowed Confidence values (ch. 6.2).
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// Valid reports whether c is an allowed Confidence value.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceHigh,
		ConfidenceMedium,
		ConfidenceLow,
		ConfidenceNone:
		return true
	}
	return false
}

// ParseConfidence parses s into a Confidence. Unknown values error.
func ParseConfidence(s string) (Confidence, error) {
	v := Confidence(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid Confidence %q", s)
	}
	return v, nil
}
