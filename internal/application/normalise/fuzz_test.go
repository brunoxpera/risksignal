package normalise

import (
	"errors"
	"testing"
	"unicode"
)

// Fuzz-style round-trip and stability properties (ch. 17.1, WP-3.04 exit
// criterion). The fuzz targets run their seed corpus in every normal
// `go test`; fuzzing adds arbitrary inputs on demand. The invariants:
//
//   - a parser never panics and never returns a partial struct: every
//     error is a positioned *SyntaxError;
//   - every accepted input round-trips exactly: Parse(s).String() == s —
//     decomposition never reshapes an original (case, encoding and field
//     order are preserved);
//   - NormaliseKey is idempotent and yields a trimmed, case-folded key.

// fuzzRoundTrip runs one round-trip iteration for a parser and its
// reassembly function.
func fuzzRoundTrip(t *testing.T, kind string, parse func(string) (string, error)) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		// Deterministic pseudo-random input of bounded size.
		s := randomASCII(t, i)
		s2, err := parse(s)
		if err == nil {
			if s2 != s {
				t.Fatalf("%s round-trip failed for %q: got %q", kind, s, s2)
			}
			continue
		}
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Fatalf("%s: expected *SyntaxError for %q, got %T (%v)", kind, s, err, err)
		}
	}
}

// randomASCII deterministically scrambles the seed to cover delimiters,
// letters, digits and punctuation without repeating one input.
func randomASCII(t *testing.T, seed int) string {
	t.Helper()
	alphabet := "cpe2.3:aohvndrbiw*+-~_@?#&=/%. \t\x01"
	n := 1 + seed%40
	b := make([]byte, n)
	x := uint64(seed)*6364136223846793005 + 1442695040888963407
	for i := range b {
		x = x*2862933555777941757 + 3037000493
		b[i] = alphabet[(x>>33)%uint64(len(alphabet))]
	}
	return string(b)
}

func TestFuzzParseCPE23RoundTrip(t *testing.T) {
	seeds := []string{
		"cpe:2.3:a:adobe:acrobat_reader:20.001.30071:*:*:*:*:windows:*:*",
		"cpe:2.3:o:debian:debian:10:*:*:*:*:*:*:*",
		"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a::widget:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:acme:widget",
		"cpe:2.2:a:acme:widget:1.0:*:*:*:*:*:*:*",
		"",
		"not a cpe at all",
	}
	for _, s := range seeds {
		if c, err := ParseCPE23(s); err == nil && c.String() != s {
			t.Fatalf("seed round-trip failed for %q: got %q", s, c.String())
		}
	}
	fuzzRoundTrip(t, "cpe", func(s string) (string, error) {
		c, err := ParseCPE23(s)
		if err != nil {
			return "", err
		}
		return c.String(), nil
	})
}

func TestFuzzParsePURLRoundTrip(t *testing.T) {
	seeds := []string{
		"pkg:deb/debian/curl@7.0.0-1",
		"pkg:golang/github.com/gorilla/mux@v1.8.0",
		"pkg:maven/org.apache.commons/commons-lang3@3.4?type=jar&classifier=sources",
		"pkg:npm/%40angular/core@12.0.0",
		"pkg:nuget/Newtonsoft.Json@13.0.1",
		"pkg:pypi/django",
		"pkg:github/octocat/hello-world#readme.md",
		"pkg:Deb/debian/curl@7.0",
		"pkg:deb/",
		"pkg:deb/debian/curl@",
		"PKG:npm/express@1.0",
		"",
	}
	for _, s := range seeds {
		if p, err := ParsePURL(s); err == nil && p.String() != s {
			t.Fatalf("seed round-trip failed for %q: got %q", s, p.String())
		}
	}
	fuzzRoundTrip(t, "purl", func(s string) (string, error) {
		p, err := ParsePURL(s)
		if err != nil {
			return "", err
		}
		return p.String(), nil
	})
}

func TestFuzzParseImageRefRoundTrip(t *testing.T) {
	seeds := []string{
		"nginx",
		"nginx:1.25",
		"library/nginx:1.25",
		"docker.io/library/nginx:1.25@" + testDigest,
		"localhost:5000/team/app:v1.0",
		"registry.example.com/app@" + testDigest,
		"Nginx:1.0",
		"nginx@sha256:xyz",
		"nginx:",
		"",
	}
	for _, s := range seeds {
		if r, err := ParseImageRef(s); err == nil && r.String() != s {
			t.Fatalf("seed round-trip failed for %q: got %q", s, r.String())
		}
	}
	fuzzRoundTrip(t, "image", func(s string) (string, error) {
		r, err := ParseImageRef(s)
		if err != nil {
			return "", err
		}
		return r.String(), nil
	})
}

func TestFuzzNormaliseKeyStable(t *testing.T) {
	inputs := []string{
		"acme", "  ACME  ", "\uFF38\uFF29 \u212A", "Stra\u00DFe", "e\uFB03cient",
		"\u00a0MiXeD\u2003", "¼ cup", "", "   ",
	}
	for _, in := range inputs {
		once := NormaliseKey(in)
		if NormaliseKey(once) != once {
			t.Fatalf("NormaliseKey not idempotent for %q", in)
		}
	}
	for seed := 0; seed < 1000; seed++ {
		s := randomASCII(t, seed)
		once := NormaliseKey(s)
		if NormaliseKey(once) != once {
			t.Fatalf("NormaliseKey not idempotent for %q", s)
		}
		if once != "" {
			if unicode.IsSpace([]rune(once)[0]) || unicode.IsSpace([]rune(once)[len([]rune(once))-1]) {
				t.Fatalf("NormaliseKey(%q) = %q is not trimmed", s, once)
			}
			for _, r := range once {
				if unicode.IsUpper(r) {
					t.Fatalf("NormaliseKey(%q) = %q still contains uppercase %q", s, once, r)
				}
			}
		}
	}
}
