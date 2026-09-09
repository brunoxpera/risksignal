package normalise

import (
	"errors"
	"strings"
	"testing"
)

// CPE 2.3 decomposition tests (ARCH-003 §2 item 3): valid strings
// decompose field by field and round-trip; malformed strings are
// positioned *SyntaxError values — never a silent default or a partial
// struct.

func TestParseCPE23Valid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want CPE23
	}{
		{
			name: "nvd-style application cpe",
			in:   "cpe:2.3:a:adobe:acrobat_reader:20.001.30071:*:*:*:*:windows:*:*",
			want: CPE23{
				Part: "a", Vendor: "adobe", Product: "acrobat_reader",
				Version: "20.001.30071", Update: "*", Edition: "*",
				Language: "*", SWEdition: "*", TargetSW: "windows",
				TargetHW: "*", Other: "*",
			},
		},
		{
			name: "operating system cpe",
			in:   "cpe:2.3:o:debian:debian:10:*:*:*:*:*:*:*",
			want: CPE23{
				Part: "o", Vendor: "debian", Product: "debian", Version: "10",
				Update: "*", Edition: "*", Language: "*", SWEdition: "*",
				TargetSW: "*", TargetHW: "*", Other: "*",
			},
		},
		{
			name: "hardware part",
			in:   "cpe:2.3:h:cisco:router:1.0:*:*:*:*:*:*:*",
			want: CPE23{
				Part: "h", Vendor: "cisco", Product: "router", Version: "1.0",
				Update: "*", Edition: "*", Language: "*", SWEdition: "*",
				TargetSW: "*", TargetHW: "*", Other: "*",
			},
		},
		{
			name: "na markers preserved",
			in:   "cpe:2.3:a:acme:widget:-:1.0:-:*:*:*:*:*",
			want: CPE23{
				Part: "a", Vendor: "acme", Product: "widget",
				Version: "-", Update: "1.0", Edition: "-",
				Language: "*", SWEdition: "*", TargetSW: "*", TargetHW: "*", Other: "*",
			},
		},
		{
			name: "all fields populated",
			in:   "cpe:2.3:a:acme:widget:1.0:u1:e1:l1:se1:tsw:thw:o1",
			want: CPE23{
				Part: "a", Vendor: "acme", Product: "widget", Version: "1.0",
				Update: "u1", Edition: "e1", Language: "l1", SWEdition: "se1",
				TargetSW: "tsw", TargetHW: "thw", Other: "o1",
			},
		},
	}
	for _, tc := range cases {
		got, err := ParseCPE23(tc.in)
		if err != nil {
			t.Errorf("%s: ParseCPE23(%q): unexpected error: %v", tc.name, tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: ParseCPE23(%q) = %+v, want %+v", tc.name, tc.in, got, tc.want)
		}
		if got.String() != tc.in {
			t.Errorf("%s: round-trip failed: ParseCPE23(%q).String() = %q", tc.name, tc.in, got.String())
		}
	}
}

// assertSyntaxError checks that err is a positioned *SyntaxError with the
// expected kind, field and index (the position/reason pair of ARCH-003
// §1.3) and that it carries the offending input verbatim.
func assertSyntaxError(t *testing.T, err error, kind, field string, index int, input string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s syntax error, got nil", kind)
	}
	var se *SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SyntaxError, got %T (%v)", err, err)
	}
	if se.Kind != kind {
		t.Errorf("SyntaxError.Kind = %q, want %q", se.Kind, kind)
	}
	if se.Field != field {
		t.Errorf("SyntaxError.Field = %q, want %q", se.Field, field)
	}
	if se.Index != index {
		t.Errorf("SyntaxError.Index = %d, want %d", se.Index, index)
	}
	if se.Input != input {
		t.Errorf("SyntaxError.Input = %q, want %q", se.Input, input)
	}
	if se.Error() == "" {
		t.Error("SyntaxError.Error() must not be empty")
	}
}

func TestParseCPE23Malformed(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		field string
		index int
	}{
		{"empty", "", "", 0},
		{"too few fields", "cpe:2.3:a:acme:widget:*:*:*:*:*:*", "", 0},
		{"too many fields", "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*:extra", "", 0},
		{"wrong scheme case", "CPE:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "", 0},
		{"wrong binding", "cpe:2.2:a:acme:widget:1.0:*:*:*:*:*:*:*", "", 0},
		{"no prefix at all", "a:acme:widget:1.0:*:*:*:*:*:*:*", "", 0},
		{"unknown part", "cpe:2.3:x:acme:widget:1.0:*:*:*:*:*:*:*", "part", 1},
		{"empty vendor", "cpe:2.3:a::widget:1.0:*:*:*:*:*:*:*", "vendor", 2},
		{"empty version", "cpe:2.3:a:acme:widget::*:*:*:*:*:*:*", "version", 4},
		{"empty other", "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:", "other", 11},
		{"control char in product", "cpe:2.3:a:acme:wid\u0001get:1.0:*:*:*:*:*:*:*", "product", 3},
	}
	for _, tc := range cases {
		_, err := ParseCPE23(tc.in)
		assertSyntaxError(t, err, "cpe", tc.field, tc.index, tc.in)
		if tc.field != "" && !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: error %q should name the field %q", tc.name, err, tc.field)
		}
	}
}

// TestParseCPE23WildcardsAllowed asserts "*" (ANY) and "-" (NA) are valid
// in every attribute — the NVD criteria vocabulary (part included, where
// only a/h/o are valid).
func TestParseCPE23WildcardsAllowed(t *testing.T) {
	_, err := ParseCPE23("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("all-wildcard CPE must parse, got %v", err)
	}
	if _, err := ParseCPE23("cpe:2.3:*:acme:widget:1.0:*:*:*:*:*:*:*"); err == nil {
		t.Error("wildcard part must be rejected (part is a/h/o)")
	}
}

// TestCPE23ValuesVerbatim asserts the decomposer never reshapes a value:
// case and spelling are preserved (case folding is the comparison-key
// concern of the caller, not of the parser).
func TestCPE23ValuesVerbatim(t *testing.T) {
	c, err := ParseCPE23("cpe:2.3:a:ACME:Widget:1.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if c.Vendor != "ACME" || c.Product != "Widget" {
		t.Errorf("values must stay verbatim, got vendor %q product %q", c.Vendor, c.Product)
	}
}
