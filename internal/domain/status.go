package domain

import "fmt"

// SignalStatus is the lifecycle state of a risk signal (ch. 6.2). The domain
// vocabulary is the ch. 6.2 set; the ch. 6.3 state machine is the pure
// transition matrix below (Transition/CanTransition) — a signal is created
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

// IsClosed reports whether s is a closed state (ch. 6.3): resolved, accepted
// or not_affected. Entering a closed state stamps closed_at (application
// layer) and starts the retention countdown; a reopen (→ in_review) clears
// it and stops the countdown.
func (s SignalStatus) IsClosed() bool {
	switch s {
	case SignalStatusResolved, SignalStatusAccepted, SignalStatusNotAffected:
		return true
	}
	return false
}

// signalTransitions is the ch. 6.3 transition matrix of ARCH-004 §2: the
// exact set of allowed edges. Every pair not listed — including every
// self-transition and new → resolved — is invalid. The matrix is data, not
// code, so it is easy to audit against the concept and exhaustively test.
var signalTransitions = map[SignalStatus]map[SignalStatus]bool{
	SignalStatusNew: {
		SignalStatusInReview:      true, // explicit acknowledgement
		SignalStatusActionPlanned: true, // impact plausible/confirmed
		SignalStatusNotAffected:   true, // reason + evidence documented
	},
	SignalStatusInReview: {
		SignalStatusActionPlanned: true,
		SignalStatusNotAffected:   true,
		SignalStatusAccepted:      true, // acceptance decision + reason + decider
	},
	SignalStatusActionPlanned: {
		SignalStatusAccepted: true,
		SignalStatusResolved: true, // measure/verification documented; closed_at set
	},
	SignalStatusResolved: {
		SignalStatusInReview: true, // reopen with mandatory reason
	},
	SignalStatusAccepted: {
		SignalStatusInReview: true, // reopen with mandatory reason
	},
	SignalStatusNotAffected: {
		SignalStatusInReview: true, // reopen with mandatory reason
	},
}

// CanTransition reports whether the from → to edge is allowed by the ch. 6.3
// matrix. Unknown states and self-transitions are never allowed.
func CanTransition(from, to SignalStatus) bool {
	if from == to {
		return false
	}
	m, ok := signalTransitions[from]
	return ok && m[to]
}

// Transition validates a status change against the ch. 6.3 matrix and
// returns a descriptive error for an off-matrix edge (TR-001). The caller
// supplies the mandatory reason for the guarded transitions (see
// TransitionRequiresReason) and writes the audit event inside the same
// command transaction — a transition that returns an error must not write
// one.
func Transition(from, to SignalStatus) error {
	if !from.Valid() {
		return fmt.Errorf("domain: invalid SignalStatus %q", from)
	}
	if !to.Valid() {
		return fmt.Errorf("domain: invalid SignalStatus %q", to)
	}
	if from == to {
		return fmt.Errorf("domain: signal status cannot transition from %q to itself", from)
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("domain: signal status transition %s -> %s is not allowed", from, to)
	}
	return nil
}

// IsReopen reports whether from → to is a reopen: a closed state back to
// in_review (ch. 6.3). A reopen carries a mandatory reason and a fresh SLA
// treatment; the closed_at retention countdown stops.
func IsReopen(from, to SignalStatus) bool {
	return from.IsClosed() && to == SignalStatusInReview && CanTransition(from, to)
}

// TransitionRequiresReason reports whether the transition must carry a
// mandatory reason (ch. 6.3): entering a closed state (not_affected,
// accepted, resolved) or reopening a closed signal. An off-matrix edge is
// false — its error is Transition's job.
func TransitionRequiresReason(from, to SignalStatus) bool {
	if !CanTransition(from, to) {
		return false
	}
	if to.IsClosed() {
		return true
	}
	return IsReopen(from, to)
}
