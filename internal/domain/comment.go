package domain

import (
	"fmt"
	"strings"
)

// Comment is one append-only comment on a risk signal (ARCH-004 §2.2,
// ch. 12.3). It is a value object: it is never edited or deleted, every
// comment is also an audit event (signal.commented) written in the same
// transaction, and the timeline read is ordered by (signal_id, created_at).
// created_at belongs to the application layer behind the clock port.
//
// ActorID is the opaque author id (a user id once I5a resolves users, a
// system principal before that).
type Comment struct {
	ID       string
	SignalID string
	ActorID  string
	Body     string
}

// NewComment validates and assembles an append-only comment: identity,
// signal reference, author and a non-blank body are required.
func NewComment(id, signalID, actorID, body string) (Comment, error) {
	if id == "" {
		return Comment{}, fmt.Errorf("domain: comment id must not be empty")
	}
	if signalID == "" {
		return Comment{}, fmt.Errorf("domain: comment signal_id must not be empty")
	}
	if actorID == "" {
		return Comment{}, fmt.Errorf("domain: comment actor_id must not be empty")
	}
	if strings.TrimSpace(body) == "" {
		return Comment{}, fmt.Errorf("domain: comment body must not be empty")
	}
	return Comment{
		ID:       id,
		SignalID: signalID,
		ActorID:  actorID,
		Body:     body,
	}, nil
}
