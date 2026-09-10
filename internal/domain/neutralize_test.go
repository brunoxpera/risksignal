package domain

import "testing"

// TestNeutralizeCSVField covers the ARCH-007 §1.3 dangerous-prefix rule: the
// six spreadsheet prefixes are neutralised with a leading single quote and
// every other cell is returned verbatim.
func TestNeutralizeCSVField(t *testing.T) {
	dangerous := []struct {
		name string
		in   string
	}{
		{"equals", "=cmd|' /C calc'!A0"},
		{"plus", "+1+1"},
		{"minus", "-2+3"},
		{"at", "@SUM(1+9)"},
		{"tab", "\tleading tab"},
		{"carriage return", "\rleading CR"},
	}
	for _, tc := range dangerous {
		t.Run(tc.name, func(t *testing.T) {
			got := NeutralizeCSVField(tc.in)
			if got != "'"+tc.in {
				t.Errorf("NeutralizeCSVField(%q) = %q, want %q", tc.in, got, "'"+tc.in)
			}
			// The mitigation is idempotent: the prepended quote is a safe
			// first rune, so a second pass is a no-op.
			if again := NeutralizeCSVField(got); again != got {
				t.Errorf("NeutralizeCSVField(%q) = %q, want the idempotent %q", got, again, got)
			}
		})
	}

	safe := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"plain", "hello"},
		{"cve id", "CVE-2021-44228"},
		{"separator inside", "a=b+c@d"},
		{"space before prefix", " =cmd"},
		{"leading digit", "9mm"},
		{"non-ascii prefix", "Über"},
		{"multibyte", "日本製品"},
	}
	for _, tc := range safe {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeutralizeCSVField(tc.in); got != tc.in {
				t.Errorf("NeutralizeCSVField(%q) = %q, want it unchanged", tc.in, got)
			}
		})
	}
}
