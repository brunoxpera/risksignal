package normalise

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// This file implements the write-time comparison-key fold of ARCH-003 §2
// item 1: NFKC normalisation (collapses Unicode compatibility forms —
// ligatures, circled/width variants, compatibility ideographs), Unicode
// trim and a case fold, applied to vendor/product before they are stored
// as components.vendor_norm / product_norm. Originals are preserved
// verbatim by the caller; aliases are deliberately NOT applied here —
// alias resolution is a match-time concern (the alias closure of
// alias.go), so an alias ruleset change never rewrites components
// (ARCH-003 §2 "Splitting these keeps alias changes cheap").
//
// The fold is the same for vendor and product; there is no punctuation
// handling in this function — punctuation and spelling variants are
// controlled through alias_rules (ARCH-003 §2 item 2).
//
// Case folding is the simple fold of strings.ToLower, applied after NFKC
// (so compatibility characters that fold via an uppercase compatibility
// form — e.g. the Kelvin sign — land lowercase too). It is not the full
// Unicode case fold: the sharp s ("ß") stays "ß" rather than expanding to
// "ss". Full folding would need x/text/cases and would change identifier
// length; the simple fold covers practical inventory comparisons and keeps
// the key deterministic.

// NormaliseKey folds one write-time comparison key (vendor_norm /
// product_norm, ARCH-003 §2 item 1): Unicode-aware trim (Unicode
// whitespace at both ends), then NFKC, then the simple lowercase fold.
// The result is the canonical spelling comparison keys and the product
// index (IX components_product_idx ON (vendor_norm, product_norm),
// ADR-012) are built on. The fold is idempotent:
// NormaliseKey(NormaliseKey(s)) == NormaliseKey(s) — a repeated import
// over already-normalised keys is stable.
func NormaliseKey(s string) string {
	return strings.ToLower(norm.NFKC.String(strings.TrimSpace(s)))
}
