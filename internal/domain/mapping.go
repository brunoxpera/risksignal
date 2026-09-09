package domain

import "fmt"

// MatchRuleVersion tags the hard-coded ADR-015 method→confidence/score
// mapping below (ARCH-001 §1 matches.rule_version). It is the placeholder
// for the versioned rule configuration. I3 matching replaces it with the
// composite ruleset version derived from the alias_rules and
// decision_rules version counters — RulesetVersion — which the matching
// use case computes and stamps on every match row; the I1b synthetic path
// keeps this constant.
const MatchRuleVersion = "i1b-1"

// RulesetVersion derives the effective matching rule version (ARCH-003
// §1.4/§3): the composite "a<alias.version>d<decision.version>" of the
// current alias_rules and decision_rules version counters — a change to
// either table bumps the composite, which flows into matches.rule_version
// and the matching.rebuild dedupe key. The counters are the monotonic
// rule versions of the two tables (0 when a table has no rules yet);
// negative counters are a caller error.
func RulesetVersion(aliasVersion, decisionVersion int) (string, error) {
	if aliasVersion < 0 {
		return "", fmt.Errorf("domain: ruleset version: alias version %d must be >= 0", aliasVersion)
	}
	if decisionVersion < 0 {
		return "", fmt.Errorf("domain: ruleset version: decision version %d must be >= 0", decisionVersion)
	}
	return fmt.Sprintf("a%dd%d", aliasVersion, decisionVersion), nil
}

// candidateScoreMin and candidateScoreMax bound the actually computed
// candidate similarity. ADR-015 reserves the 1–54 band for candidate: below
// the deterministic ranks (55..100), above no_match (0).
const (
	candidateScoreMin = 1
	candidateScoreMax = 54
)

// matchRule is one row of the ADR-015 mapping (ch. 9.2): the confidence the
// method implies and the fixed sort rank. Candidate has no fixed score — its
// rank is the actually computed similarity — so its row only carries the
// confidence (low).
type matchRule struct {
	confidence Confidence
	score      int
}

// matchRules is the versioned mapping table (rule_version "i1b-1"). A new
// matching method is a new enum value plus one row here and nowhere else
// (ADR-015 decision: no argument about numbers).
var matchRules = map[MatchMethod]matchRule{
	MatchMethodExactIdentifier:         {confidence: ConfidenceHigh, score: 100},
	MatchMethodContainerDigest:         {confidence: ConfidenceHigh, score: 95},
	MatchMethodAliasExactVersion:       {confidence: ConfidenceHigh, score: 90},
	MatchMethodCanonicalProductRange:   {confidence: ConfidenceHigh, score: 80},
	MatchMethodProductUncertainVersion: {confidence: ConfidenceMedium, score: 65},
	MatchMethodControlledAliasOnly:     {confidence: ConfidenceMedium, score: 55},
	MatchMethodCandidate:               {confidence: ConfidenceLow}, // score: computed similarity
	MatchMethodNoMatch:                 {confidence: ConfidenceNone, score: 0},
}

// Confidence reports the confidence ADR-015 derives from the method (ch. 9.2).
// ok is false for an unknown method value — a caller must not fall back to a
// silent default, because the ch. 9.3 rules read exactly this value.
func (m MatchMethod) Confidence() (conf Confidence, ok bool) {
	r, ok := matchRules[m]
	return r.confidence, ok
}

// Derive returns the confidence and the derived sort-rank score for the
// method (ADR-015, ch. 9.2). The method is authoritative; confidence and
// score are derived, never independently stored.
//
// similarity is the actually computed similarity and only read for candidate,
// where it must lie in [candidateScoreMin, candidateScoreMax] (1–54); every
// other method ignores it. Derive errors on unknown methods and on candidate
// similarities outside the band.
func (m MatchMethod) Derive(similarity int) (conf Confidence, score int, err error) {
	r, ok := matchRules[m]
	if !ok {
		return "", 0, fmt.Errorf("domain: cannot derive match for unknown method %q", m)
	}
	if m == MatchMethodCandidate {
		if similarity < candidateScoreMin || similarity > candidateScoreMax {
			return "", 0, fmt.Errorf("domain: candidate similarity %d outside [%d,%d]", similarity, candidateScoreMin, candidateScoreMax)
		}
		return r.confidence, similarity, nil
	}
	return r.confidence, r.score, nil
}
