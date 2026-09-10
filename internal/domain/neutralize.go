package domain

import "unicode/utf8"

// NeutralizeCSVField neutralises one CSV cell against spreadsheet formula
// injection (ARCH-007 §1.3/§11.2/§12.3, OWASP "CSV Injection"): when the
// cell's first rune is one of the dangerous spreadsheet prefixes
// '=', '+', '-', '@', TAB or CR, a single ASCII apostrophe is prepended so
// a consumer spreadsheet reads the cell as text instead of evaluating it as
// formula. Every other cell is returned unchanged.
//
// The function is the single, uniform mitigation the CSV export writer
// applies to *every* cell — the header row and each data row, never only to
// "suspected" fields — so a user-controlled product/CVE/owner/free-text
// value can never survive as a formula (ARCH-007 §1.3). It is pure and
// deterministic (same input ⇒ same output), depends only on the standard
// library and imports nothing outside it, so the domain layer stays free of
// adapter/generated-code dependencies (go-arch-lint gate, .go-arch-lint.yml).
//
// Only the first rune is inspected: a separator inside the value ('a=b') is
// not a formula and is left untouched. The neutralisation is idempotent —
// re-neutralising an already-prefixed cell is a no-op, because the prepended
// apostrophe is itself a safe first rune.
func NeutralizeCSVField(s string) string {
	if s == "" {
		return s
	}
	r, _ := utf8.DecodeRuneInString(s)
	switch r {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	default:
		return s
	}
}
