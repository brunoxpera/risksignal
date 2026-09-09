package domain

import "fmt"

// SignalStatus is the lifecycle state of a risk signal (ch. 6.2). The domain
// defines the full vocabulary; it deliberately implements no transitions —
// the state machine of ch. 6.3 arrives with I4. I1b always creates signals
// with status new (ARCH-001 §1 risk_signals.status DEFAULT 'new').
type SignalStatus string

// Allowed SignalStatus values (ch. 6.2).
const (
	SignalStatusNew           SignalStatus = "new"
	SignalStatusInReview      SignalStatus = "in_review"
	SignalStatusActionPlanned SignalStatus = "action_planned"
	SignalStatusResolved      SignalStatus = "resolved"
	SignalStatusAccepted      SignalStatus = "accepted"
	SignalStatusNotAffected   SignalStatus = "not_affected"
)

// Valid reports whether s is an allowed SignalStatus value.
func (s SignalStatus) Valid() bool {
	switch s {
	case SignalStatusNew,
		SignalStatusInReview,
		SignalStatusActionPlanned,
		SignalStatusResolved,
		SignalStatusAccepted,
		SignalStatusNotAffected:
		return true
	}
	return false
}

// ParseSignalStatus parses s into a SignalStatus. Unknown values error.
func ParseSignalStatus(s string) (SignalStatus, error) {
	v := SignalStatus(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid SignalStatus %q", s)
	}
	return v, nil
}
