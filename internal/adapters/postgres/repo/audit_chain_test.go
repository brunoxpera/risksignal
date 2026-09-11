package repo

// Unit tests for the audit chain's canonical JSON form (DEV-125 / DEV-123
// review finding #2). canonicalJSON is the shared hash input for stamping and
// verification: it must render a jsonb snapshot to the exact byte form the
// database prints back, or an untampered chain fails verification. These tests
// pin the numeric normalisation — JSON numbers are rendered the way jsonb's
// numeric type stores and prints them (plain decimal, no exponent, no leading
// zeros, no sign on zero, input scale preserved) — alongside the existing
// guarantees (sorted keys, no insignificant whitespace, empty ⇒ NULL, non-JSON
// ⇒ raw bytes, strings/booleans/null untouched).

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// jsonb numeric: exponent form collapses to plain decimal.
		{"exponent integer", `{"n":1e2}`, `{"n":100}`},
		{"upper-case exponent", `{"n":1E2}`, `{"n":100}`},
		{"explicit plus exponent", `{"n":1e+2}`, `{"n":100}`},
		{"fractional mantissa", `{"n":1.5e2}`, `{"n":150}`},
		{"scale preserved through exponent", `{"n":1.50e1}`, `{"n":15.0}`},
		{"positive exponent keeps integer", `{"n":1.0e1}`, `{"n":10}`},
		{"negative exponent adds scale", `{"n":10e-1}`, `{"n":1.0}`},
		{"negative exponent two", `{"n":100e-2}`, `{"n":1.00}`},
		{"negative exponent on integer", `{"n":12300e-2}`, `{"n":123.00}`},
		{"small value", `{"n":123e-5}`, `{"n":0.00123}`},
		{"tiny value", `{"n":1e-7}`, `{"n":0.0000001}`},
		{"large value", `{"n":1e100}`, `{"n":1` + strings.Repeat("0", 100) + `}`},
		{"leading-zero scale trims", `{"n":0.0000000001e10}`, `{"n":1}`},
		// jsonb numeric: sign is dropped from zero, scale kept.
		{"negative zero", `{"n":-0}`, `{"n":0}`},
		{"negative zero with scale", `{"n":-0.0}`, `{"n":0.0}`},
		{"negative zero three decimals", `{"n":-0.000}`, `{"n":0.000}`},
		// already-canonical numbers must not move.
		{"plain integer", `{"status":"open","version":1}`, `{"status":"open","version":1}`},
		{"plain decimal", `{"n":1.50}`, `{"n":1.50}`},
		{"trailing zero integer scale", `{"n":100.0}`, `{"n":100.0}`},
		{"plain small decimal", `{"n":0.10}`, `{"n":0.10}`},
		// keys sorted, arrays walked, non-numeric scalars untouched.
		{"keys sorted", `{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{"nested", `{"n":[1e2,{"m":2e-1}]}`, `{"n":[100,{"m":0.2}]}`},
		{"non-numbers untouched", `{"s":"1e2","b":true,"z":null}`, `{"b":true,"s":"1e2","z":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(canonicalJSON([]byte(tc.in)))
			if got != tc.want {
				t.Fatalf("canonicalJSON(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestCanonicalJSONStable pins the invariants that must survive the change:
// empty stays NULL, a non-JSON value falls back to the raw bytes, and the form
// is idempotent (hashing a value read back from jsonb — the already-canonical
// decimal form — yields the same bytes).
func TestCanonicalJSONStable(t *testing.T) {
	if got := canonicalJSON(nil); got != nil {
		t.Fatalf("canonicalJSON(nil) = %q, want nil", got)
	}
	if got := canonicalJSON([]byte{}); got != nil {
		t.Fatalf("canonicalJSON(empty) = %q, want nil", got)
	}
	raw := []byte(`{not json`)
	if got := canonicalJSON(raw); string(got) != string(raw) {
		t.Fatalf("canonicalJSON(non-JSON) = %q, want raw %q", got, raw)
	}

	for _, in := range []string{
		`{"n":1e2}`,
		`{"n":1.50e1}`,
		`{"n":-0.0}`,
		`{"b":1,"a":[2e-1,1e100]}`,
		`{"status":"open","version":1}`,
	} {
		once := canonicalJSON([]byte(in))
		twice := canonicalJSON(once)
		if string(once) != string(twice) {
			t.Fatalf("canonicalJSON not idempotent for %s: %s then %s", in, once, twice)
		}
		if !json.Valid(once) {
			t.Fatalf("canonicalJSON(%s) = %s, not valid JSON", in, once)
		}
	}
}

// TestNormaliseJSONNumberExponentBound pins the guard around the exponent
// expansion (DEV-127). PostgreSQL numeric accepts at most 131072 digits before
// the decimal point and 16383 after; anything larger is rejected by jsonb at
// insert ("value overflows numeric format"), so it never persists and the
// chain never hashes it. The expansion must therefore stay bounded for such
// input — expanding 1e999999999 would otherwise allocate roughly a gigabyte —
// while the accepted boundaries must still render exactly as jsonb prints them.
func TestNormaliseJSONNumberExponentBound(t *testing.T) {
	// Out-of-range values: rejected by jsonb at insert, so normalisation
	// returns the raw lexeme unchanged and never allocates. The bound is the
	// absence of a multi-gigabyte string; a short lexeme is the proof.
	outOfRange := []string{
		"1e999999999",  // positive exponent ~1 GB if expanded
		"1e-999999999", // negative exponent, megabyte-scale scale
		"1e131072",     // one digit past the integer limit (131072 accepted)
		"1e-131072",    // integer-scale negative exponent
		"1e-16384",     // one digit past the scale limit (16383 accepted)
	}
	for _, in := range outOfRange {
		t.Run("bounded "+in, func(t *testing.T) {
			got := normaliseJSONNumber(json.Number(in)).String()
			if got != in {
				t.Fatalf("normaliseJSONNumber(%s) = %s, want the raw lexeme unchanged", in, got)
			}
			if len(got) > 64 {
				t.Fatalf("normaliseJSONNumber(%s) returned %d bytes, want a bounded result", in, len(got))
			}
		})
	}

	// Accepted boundaries: one step inside PostgreSQL numeric's limits, these
	// must still expand to the exact plain-decimal form jsonb stores.
	if got, want := normaliseJSONNumber(json.Number("1e-16383")).String(), "0."+strings.Repeat("0", 16382)+"1"; got != want {
		t.Fatalf("normaliseJSONNumber(1e-16383) = %s, want %s", got, want)
	}
	if got, want := normaliseJSONNumber(json.Number("1e131071")).String(), "1"+strings.Repeat("0", 131071); got != want {
		t.Fatalf("normaliseJSONNumber(1e131071) = %s, want %s", got, want)
	}

	// The guard must not fire for leading zeros that numeric trims: 0.1e131072
	// is the in-range value 1e131071 and must expand (PostgreSQL accepts it).
	if got, want := normaliseJSONNumber(json.Number("0.1e131072")).String(), "1"+strings.Repeat("0", 131071); got != want {
		t.Fatalf("normaliseJSONNumber(0.1e131072) = %s, want %s", got, want)
	}
}

// TestCanonicalJSONExponentBound drives the guard through the public entry
// point: an out-of-range exponent inside a jsonb snapshot must yield a bounded
// canonical form (not a gigabyte of zeros) and stay valid JSON.
func TestCanonicalJSONExponentBound(t *testing.T) {
	for _, in := range []string{
		`{"n":1e999999999}`,
		`{"n":1e-999999999}`,
		`{"n":1e131072}`,
		`{"n":1e-16384}`,
	} {
		out := canonicalJSON([]byte(in))
		if len(out) > 64 {
			t.Fatalf("canonicalJSON(%s) produced %d bytes, want a bounded result", in, len(out))
		}
		if !json.Valid(out) {
			t.Fatalf("canonicalJSON(%s) = %s, not valid JSON", in, out)
		}
	}
}
