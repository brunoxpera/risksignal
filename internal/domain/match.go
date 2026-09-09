package domain

import "fmt"

// Match links a vulnerability to an inventory component (ch. 6.1, ARCH-001
// §1 matches). Matching is method-led (ADR-015): the method is
// authoritative and confidence plus the derived sort-rank score follow from
// it through the versioned mapping (mapping.go, tagged MatchRuleVersion) —
// they are never stored or set independently. Use NewMatch to construct a
// Match with that invariant; the field block mirrors the table columns
// (minus created_at) so the persistence layer can scan rows back into plain
// structs.
//
// Score is the sort rank of ch. 9.2 (100/95/90/80/65/55, 0 for no_match);
// only for candidate it carries the actually computed similarity. The
// uniqueness key (vulnerability_id, component_id, rule_version) makes a
// re-run idempotent at the application layer.
type Match struct {
	ID              string // uuid
	VulnerabilityID string
	ComponentID     string
	Method          MatchMethod
	Confidence      Confidence
	Score           int
	RuleVersion     string
}

// NewMatch validates and assembles a Match, deriving confidence and the
// sort-rank score from the authoritative method through the ADR-015 mapping
// (candidateSimilarity is the actually computed similarity, required for
// candidate only) and stamping the mapping rule version. Constructing a
// Match any other way risks a method/confidence/score triple the mapping
// would never produce.
func NewMatch(id, vulnerabilityID, componentID string, method MatchMethod, candidateSimilarity int) (Match, error) {
	if id == "" {
		return Match{}, fmt.Errorf("domain: match id must not be empty")
	}
	if vulnerabilityID == "" {
		return Match{}, fmt.Errorf("domain: match vulnerability_id must not be empty")
	}
	if componentID == "" {
		return Match{}, fmt.Errorf("domain: match component_id must not be empty")
	}
	conf, score, err := method.Derive(candidateSimilarity)
	if err != nil {
		return Match{}, err
	}
	return Match{
		ID:              id,
		VulnerabilityID: vulnerabilityID,
		ComponentID:     componentID,
		Method:          method,
		Confidence:      conf,
		Score:           score,
		RuleVersion:     MatchRuleVersion,
	}, nil
}
