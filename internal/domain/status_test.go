package domain

import "testing"

// signalStates is every allowed status vocabulary value (ch. 6.2).
func signalStates() []SignalStatus {
	return []SignalStatus{
		SignalStatusNew,
		SignalStatusInReview,
		SignalStatusActionPlanned,
		SignalStatusResolved,
		SignalStatusAccepted,
		SignalStatusNotAffected,
	}
}

// allowedSignalEdges is the ch. 6.3 / ARCH-004 §2 matrix as data: the exact
// set of edges CanTransition must accept.
func allowedSignalEdges() map[[2]SignalStatus]bool {
	return map[[2]SignalStatus]bool{
		{SignalStatusNew, SignalStatusInReview}:           true,
		{SignalStatusNew, SignalStatusActionPlanned}:      true,
		{SignalStatusNew, SignalStatusNotAffected}:        true,
		{SignalStatusInReview, SignalStatusActionPlanned}: true,
		{SignalStatusInReview, SignalStatusNotAffected}:   true,
		{SignalStatusInReview, SignalStatusAccepted}:      true,
		{SignalStatusActionPlanned, SignalStatusAccepted}: true,
		{SignalStatusActionPlanned, SignalStatusResolved}: true,
		{SignalStatusResolved, SignalStatusInReview}:      true,
		{SignalStatusAccepted, SignalStatusInReview}:      true,
		{SignalStatusNotAffected, SignalStatusInReview}:   true,
	}
}

// TestSignalTransitionMatrix accepts every §2 edge and rejects every
// off-matrix edge (including every self-transition and new → resolved).
func TestSignalTransitionMatrix(t *testing.T) {
	allowed := allowedSignalEdges()
	for _, from := range signalStates() {
		for _, to := range signalStates() {
			want := allowed[[2]SignalStatus{from, to}]
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%s -> %s) = %v, want %v", from, to, got, want)
			}
			err := Transition(from, to)
			if want && err != nil {
				t.Errorf("Transition(%s -> %s): unexpected error: %v", from, to, err)
			}
			if !want && err == nil {
				t.Errorf("Transition(%s -> %s): want error, got nil", from, to)
			}
		}
	}
}

// TestSignalTransitionRejectsUnknownStatus: unknown states are errors.
func TestSignalTransitionRejectsUnknownStatus(t *testing.T) {
	if err := Transition(SignalStatus("open"), SignalStatusInReview); err == nil {
		t.Error("Transition from an unknown status: want error, got nil")
	}
	if err := Transition(SignalStatusNew, SignalStatus("closed")); err == nil {
		t.Error("Transition to an unknown status: want error, got nil")
	}
}

// TestSignalStatusIsClosed pins the closed-state set.
func TestSignalStatusIsClosed(t *testing.T) {
	closed := map[SignalStatus]bool{
		SignalStatusNew:           false,
		SignalStatusInReview:      false,
		SignalStatusActionPlanned: false,
		SignalStatusResolved:      true,
		SignalStatusAccepted:      true,
		SignalStatusNotAffected:   true,
	}
	for _, s := range signalStates() {
		if got := s.IsClosed(); got != closed[s] {
			t.Errorf("IsClosed(%s) = %v, want %v", s, got, closed[s])
		}
	}
}

// TestSignalTransitionRequiresReason pins the mandatory-reason edges: every
// entry into a closed state and every reopen.
func TestSignalTransitionRequiresReason(t *testing.T) {
	want := map[[2]SignalStatus]bool{
		{SignalStatusNew, SignalStatusInReview}:           false,
		{SignalStatusNew, SignalStatusActionPlanned}:      false,
		{SignalStatusNew, SignalStatusNotAffected}:        true,
		{SignalStatusInReview, SignalStatusActionPlanned}: false,
		{SignalStatusInReview, SignalStatusNotAffected}:   true,
		{SignalStatusInReview, SignalStatusAccepted}:      true,
		{SignalStatusActionPlanned, SignalStatusAccepted}: true,
		{SignalStatusActionPlanned, SignalStatusResolved}: true,
		{SignalStatusResolved, SignalStatusInReview}:      true,
		{SignalStatusAccepted, SignalStatusInReview}:      true,
		{SignalStatusNotAffected, SignalStatusInReview}:   true,
	}
	for _, from := range signalStates() {
		for _, to := range signalStates() {
			if got := TransitionRequiresReason(from, to); got != want[[2]SignalStatus{from, to}] {
				t.Errorf("TransitionRequiresReason(%s -> %s) = %v, want %v", from, to, got, want[[2]SignalStatus{from, to}])
			}
		}
	}
}

// TestSignalIsReopen pins the reopen predicate: a closed state back to
// in_review.
func TestSignalIsReopen(t *testing.T) {
	if !IsReopen(SignalStatusResolved, SignalStatusInReview) {
		t.Error("resolved -> in_review must be a reopen")
	}
	if !IsReopen(SignalStatusNotAffected, SignalStatusInReview) {
		t.Error("not_affected -> in_review must be a reopen")
	}
	if IsReopen(SignalStatusNew, SignalStatusInReview) {
		t.Error("new -> in_review must not be a reopen")
	}
	if IsReopen(SignalStatusResolved, SignalStatusActionPlanned) {
		t.Error("resolved -> action_planned must not be a reopen")
	}
}
