package domain

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
