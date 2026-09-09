package domain

import "testing"

// Candidate similarity tests (ARCH-003 §3, ADR-015): deterministic,
// network-free, always inside the candidate band [1, 54], and never able
// to produce high confidence (the method mapping keeps candidate at low).

// TestCandidateSimilarityDeterminism: the same input pair always yields
// the same score.
func TestCandidateSimilarityDeterminism(t *testing.T) {
	pairs := [][2]string{
		{"apache http server", "apache httpd"},
		{"openssl", "OpenSSL"},
		{"mysql server", "mariadb server"},
		{"", ""},
		{"nginx", "nginx"},
	}
	for _, p := range pairs {
		first := CandidateSimilarity(p[0], p[1])
		for i := 0; i < 20; i++ {
			if got := CandidateSimilarity(p[0], p[1]); got != first {
				t.Fatalf("CandidateSimilarity(%q, %q) is not deterministic: %d then %d", p[0], p[1], first, got)
			}
		}
	}
}

// TestCandidateSimilarityBand: every score — including adversarial and
// empty inputs — lands inside [1, 54] and therefore always passes
// MatchMethodCandidate.Derive.
func TestCandidateSimilarityBand(t *testing.T) {
	inputs := []string{
		"", "apache", "apache http server", "Apache_HTTP-Server", "httpd",
		"openssl", "OpenSSL 3.0", "mysql", "postgresql database server",
		"oracle weblogic server", "nginx", "java", "libssl", "ssl",
		"a b c d e f", "zzz zzz zzz", "Kubernetes", "containerd",
	}
	for _, a := range inputs {
		for _, b := range inputs {
			s := CandidateSimilarity(a, b)
			if s < candidateScoreMin || s > candidateScoreMax {
				t.Fatalf("CandidateSimilarity(%q, %q) = %d, outside [%d,%d]", a, b, s, candidateScoreMin, candidateScoreMax)
			}
			if _, _, err := MatchMethodCandidate.Derive(s); err != nil {
				t.Fatalf("Derive(CandidateSimilarity(%q, %q)=%d): %v", a, b, s, err)
			}
		}
	}
}

// TestCandidateSimilarityAnchors: identical names score the band maximum,
// empty inputs score the band minimum (no evidence of overlap is never
// read as similarity), and closer names score above disjoint ones.
func TestCandidateSimilarityAnchors(t *testing.T) {
	identical := CandidateSimilarity("Apache HTTP Server", "apache_http_server")
	if identical != candidateScoreMax {
		t.Errorf("identical names = %d, want the band maximum %d", identical, candidateScoreMax)
	}
	for _, pair := range [][2]string{{"", ""}, {"", "apache"}, {"apache http", ""}} {
		if s := CandidateSimilarity(pair[0], pair[1]); s != candidateScoreMin {
			t.Errorf("CandidateSimilarity(%q, %q) = %d, want the band minimum %d", pair[0], pair[1], s, candidateScoreMin)
		}
	}

	similar := CandidateSimilarity("apache http server", "apache httpd")
	disjoint := CandidateSimilarity("postgresql database", "oracle weblogic")
	if similar <= disjoint {
		t.Errorf("similar pair (%d) must outscore a disjoint pair (%d)", similar, disjoint)
	}
	if similar <= candidateScoreMin || disjoint < candidateScoreMin {
		t.Errorf("anchors outside the band: similar %d, disjoint %d", similar, disjoint)
	}
	// Token order alone (a transposition) still scores high: the token
	// streams overlap completely.
	reordered := CandidateSimilarity("http server apache", "apache http server")
	if reordered < similar {
		t.Errorf("reordered identical tokens (%d) must score at least as high as similar (%d)", reordered, similar)
	}
}

// TestCandidateSimilarityNeverHighConfidence: the candidate method maps to
// low confidence whatever the computed score — fuzzy matching yields
// candidates only.
func TestCandidateSimilarityNeverHighConfidence(t *testing.T) {
	m, err := NewMatch("m1", "v1", "c1", MatchMethodCandidate, CandidateSimilarity("apache http server", "apache httpd"))
	if err != nil {
		t.Fatalf("NewMatch(candidate): unexpected error: %v", err)
	}
	if m.Confidence != ConfidenceLow {
		t.Errorf("candidate match confidence = %q, want low (never high)", m.Confidence)
	}
	if m.Score < candidateScoreMin || m.Score > candidateScoreMax {
		t.Errorf("candidate match score = %d, outside [%d,%d]", m.Score, candidateScoreMin, candidateScoreMax)
	}
}

// TestCandidateSimilaritySymmetry: the score is a symmetric function of
// its two arguments (callers may pass either side first).
func TestCandidateSimilaritySymmetry(t *testing.T) {
	pairs := [][2]string{
		{"apache http server", "apache httpd"},
		{"mysql", "mariadb"},
		{"nginx", "openresty"},
	}
	for _, p := range pairs {
		if ab, ba := CandidateSimilarity(p[0], p[1]), CandidateSimilarity(p[1], p[0]); ab != ba {
			t.Errorf("CandidateSimilarity(%q, %q)=%d but reversed = %d", p[0], p[1], ab, ba)
		}
	}
}
