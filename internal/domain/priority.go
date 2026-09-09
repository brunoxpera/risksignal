package domain

import "fmt"

// Priority is the urgency class of a risk signal (ch. 6.2, ch. 9.3). P1 is
// the most urgent. The priority of a signal is computed by the deterministic
// ch. 9.3 rules (priority_rules.go, tagged PriorityRuleVersion) from the
// stored factors; the rule version and the contributing factors are stored
// with the signal (ARCH-001 §1 risk_signals.rule_version/factors, ch. 9.5).
type Priority string

// Allowed Priority values (ch. 6.2).
const (
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
	PriorityP4 Priority = "P4"
)

// Valid reports whether p is an allowed Priority value.
func (p Priority) Valid() bool {
	switch p {
	case PriorityP1,
		PriorityP2,
		PriorityP3,
		PriorityP4:
		return true
	}
	return false
}

// ParsePriority parses s into a Priority. Unknown values error.
func ParsePriority(s string) (Priority, error) {
	v := Priority(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid Priority %q", s)
	}
	return v, nil
}
