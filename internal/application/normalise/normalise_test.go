package normalise

import "testing"

// NormaliseKey tests (ARCH-003 §2 item 1): the write-time comparison-key
// fold behind vendor_norm/product_norm — Unicode trim, NFKC and the
// lowercase case fold. Originals are preserved verbatim by the caller;
// this function only derives the key.

// TestNormaliseKey covers the fold: trim (incl. Unicode whitespace),
// compatibility normalisation (ligatures, width variants, the Kelvin
// sign) and the case fold.
func TestNormaliseKey(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "acme", "acme"},
		{"simple case fold", "ACME", "acme"},
		{"trim", "  acme  ", "acme"},
		{"unicode whitespace trim", "\u00a0\u2003acme\u2003\u00a0", "acme"},
		{"ligature decomposes", "e\uFB03cient", "efficient"}, // ﬁ -> fi
		{"fullwidth folds", "\uFF21\uFF23\uFF2D\uFF25", "acme"},
		{"kelvin sign folds via NFKC then lower", "\u212A", "k"},      // K (kelvin) -> k
		{"sharp s stays simple-folded", "Stra\u00DFe", "stra\u00DFe"}, // ß stays ß
		{"empty", "", ""},
		{"only whitespace", " \t\u00a0 ", ""},
		{"mixed case and spaces", "  Adobe\u00ae  ", "adobe\u00ae"},
	}
	for _, tc := range cases {
		if got := NormaliseKey(tc.in); got != tc.want {
			t.Errorf("NormaliseKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNormaliseKeyIdempotent asserts the fold is stable: re-folding an
// already-normalised key is a no-op, so repeated imports over stored
// comparison keys never drift.
func TestNormaliseKeyIdempotent(t *testing.T) {
	inputs := []string{
		"acme", "  ACME Corp  ", "\uFF38Per\uFF29a\u212A", "Stra\u00DFe",
		"\u00a0\u2003MiXeD\u2003\u00a0", "", "   ",
	}
	for _, in := range inputs {
		once := NormaliseKey(in)
		twice := NormaliseKey(once)
		if once != twice {
			t.Errorf("NormaliseKey not idempotent: NormaliseKey(%q) = %q, NormaliseKey(%q) = %q", in, once, once, twice)
		}
		if twice != once {
			t.Errorf("NormaliseKey unstable for %q", in)
		}
	}
}

// TestNormaliseKeyDeterministic asserts same input => same output across
// the two canonical spellings of one vendor name (the determinism
// contract of the product index, ADR-012).
func TestNormaliseKeyDeterministic(t *testing.T) {
	if NormaliseKey("Oracle") != NormaliseKey("oracle") {
		t.Error("Oracle and oracle must fold identically")
	}
	if NormaliseKey("  IBM  ") != NormaliseKey("ibm") {
		t.Error("trimmed IBM must fold like ibm")
	}
}
