package domain

import "testing"

// TestNewComment covers the accepted shape and the rejected invariants of
// the append-only comment value object.
func TestNewComment(t *testing.T) {
	c, err := NewComment("c1", "s1", "actor-1", "looks exploited in prod")
	if err != nil {
		t.Fatalf("NewComment: unexpected error: %v", err)
	}
	if c.ID != "c1" || c.SignalID != "s1" || c.ActorID != "actor-1" || c.Body != "looks exploited in prod" {
		t.Errorf("NewComment = %+v, want the input fields", c)
	}

	rejected := []struct {
		name                        string
		id, signalID, actorID, body string
	}{
		{"empty id", "", "s1", "a", "body"},
		{"empty signal_id", "c1", "", "a", "body"},
		{"empty actor_id", "c1", "s1", "", "body"},
		{"empty body", "c1", "s1", "a", ""},
		{"blank body", "c1", "s1", "a", "   \t\n"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewComment(tc.id, tc.signalID, tc.actorID, tc.body); err == nil {
				t.Errorf("NewComment(%s): want error, got nil", tc.name)
			}
		})
	}
}
