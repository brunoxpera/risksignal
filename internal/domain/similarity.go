package domain

import (
	"strings"
	"unicode"
)

// Candidate similarity (ADR-015, ch. 9.2; ARCH-003 §3 "candidate
// similarity"): the only match score that carries real information — every
// other method's rank is a fixed constant of the ADR-015 mapping. It is a
// deterministic, pure function over the normalised product names: a
// token-based Jaccard overlap combined with a bounded Damerau-Levenshtein
// edit distance over the token stream, scaled into the candidate score
// band [1, 54].
//
// Determinism and the band are the contract: the same two names always
// yield the same score, the score always lands inside [candidateScoreMin,
// candidateScoreMax] and fuzzy matching can never produce high confidence —
// the method candidate maps to ConfidenceLow through the versioned
// mapping (mapping.go), whatever the score.

// candidateSimilarityDLBound caps the Damerau-Levenshtein distance over
// the token stream: distances at or beyond the cap all map to the same
// similarity contribution, which is what makes the edit distance "bounded"
// and keeps very different names from receiving ever-lower scores through
// the distance term alone.
const candidateSimilarityDLBound = 3

// CandidateSimilarity scores the similarity of two normalised product
// names on the candidate band [1, 54]. The inputs are the comparison keys
// of ARCH-003 §2 (product_norm and the CVE-side normalised product name);
// the function still case-folds and tokenises defensively.
//
//	score = 1 + floor(53 * (0.6 * tokenJaccard + 0.4 * boundedDLSim))
//
// with boundedDLSim = 1 - min(dl, 3)/3 over the token streams. Identical
// names score the band maximum 54; an empty input (no tokens on either
// side) scores the band minimum 1 — there is no evidence of overlap and
// the matcher must not invent one.
func CandidateSimilarity(a, b string) int {
	ta, tb := tokenise(a), tokenise(b)
	if len(ta) == 0 || len(tb) == 0 {
		return candidateScoreMin
	}
	jac := tokenJaccard(ta, tb)
	dl := boundedDamerauLevenshtein(ta, tb, candidateSimilarityDLBound)
	dlSim := 1.0 - float64(dl)/float64(candidateSimilarityDLBound)
	sim := 0.6*jac + 0.4*dlSim
	score := candidateScoreMin + int(sim*float64(candidateScoreMax-candidateScoreMin))
	if score < candidateScoreMin {
		return candidateScoreMin
	}
	if score > candidateScoreMax {
		return candidateScoreMax
	}
	return score
}

// tokenise splits a normalised product name into its alphanumeric word
// tokens, case-folded: runs of letters and digits separated by anything
// else ("Apache-HTTP_Server" and "apache http server" tokenise alike).
func tokenise(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// tokenJaccard is the classic set-based Jaccard overlap of the two token
// streams (|A∩B| / |A∪B|; 1 for identical token sets, 0 for disjoint).
// Duplicates within one name count once — the overlap is about vocabulary,
// not repetition.
func tokenJaccard(a, b []string) float64 {
	setA := make(map[string]struct{}, len(a))
	for _, t := range a {
		setA[t] = struct{}{}
	}
	intersection, union := 0, len(setA)
	seen := make(map[string]struct{}, len(b))
	for _, t := range b {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		if _, ok := setA[t]; ok {
			intersection++
		} else {
			union++
		}
	}
	if union == 0 {
		return 1 // both streams empty: handled by the caller
	}
	return float64(intersection) / float64(union)
}

// boundedDamerauLevenshtein computes the Damerau-Levenshtein distance
// (unit insert/delete/substitute/transpose costs, unrestricted
// transpositions — the Lowrance-Wagner algorithm) between the two token
// streams, capped at cap: any true distance >= cap is returned as cap.
// Tokens are compared as whole symbols (the streams' elements, not their
// characters), which is the "edit distance on the token stream" of
// ARCH-003 §3.
func boundedDamerauLevenshtein(a, b []string, cap int) int {
	m, n := len(a), len(b)
	if m == 0 {
		if n > cap {
			return cap
		}
		return n
	}
	if n == 0 {
		if m > cap {
			return cap
		}
		return m
	}
	// d is indexed [0..m+1][0..n+1] with the Lowrance-Wagner sentinel
	// seeding: row/column 0 carries maxDist, the first row/column of real
	// cells carries the prefix costs (d[1][j] = j-1, d[i][1] = i-1) and
	// d[0][0] the sentinel.
	maxDist := m + n
	d := make([][]int, m+2)
	for i := range d {
		d[i] = make([]int, n+2)
	}
	d[0][0] = maxDist
	for i := 0; i <= m; i++ {
		d[i+1][0] = maxDist
		d[i+1][1] = i
	}
	for j := 0; j <= n; j++ {
		d[0][j+1] = maxDist
		d[1][j+1] = j
	}
	lastSeen := make(map[string]int, len(a)+len(b)) // token → last row index
	for i := 1; i <= m; i++ {
		db := 0
		for j := 1; j <= n; j++ {
			k := lastSeen[b[j-1]]
			l := db
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
				db = j
			}
			sub := d[i][j] + cost
			ins := d[i+1][j] + 1
			del := d[i][j+1] + 1
			trans := d[k][l] + (i - k - 1) + 1 + (j - l - 1)
			best := sub
			if ins < best {
				best = ins
			}
			if del < best {
				best = del
			}
			if trans < best {
				best = trans
			}
			d[i+1][j+1] = best
		}
		lastSeen[a[i-1]] = i
	}
	dist := d[m+1][n+1]
	if dist > cap {
		return cap
	}
	return dist
}
