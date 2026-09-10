package application

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Working-list pagination bounds (ARCH-001 §4 listSignals: limit default 20,
// max 100). Cursors are opaque to callers; the encoding below is a private
// page-state token and may change between releases.
const (
	defaultListLimit = 20
	maxListLimit     = 100
)

// ListSignalsInput is the working-list query (ARCH-001 §4): optional
// priority/status filters, an opaque cursor and a page size. Limit 0 means
// the default (20); limits above maxListLimit are rejected. Actor is the
// authenticated principal: signals.read is gated per the matrix and an
// `assigned`/`own` grant restricts the read to the principal's owned signals
// (ARCH-005 §5).
type ListSignalsInput struct {
	Limit    int
	Cursor   string
	Priority *domain.Priority
	Status   *domain.SignalStatus
	Actor    Actor
}

// ListSignalsResult is one page of the working list. NextCursor is empty on
// the last page.
type ListSignalsResult struct {
	Signals    []Signal
	NextCursor string
}

// pageCursor is the decoded state of an opaque cursor: the row offset into
// the stable working-list order (priority P1→P4, then created_at, then id —
// ARCH-001 §4 / ch. 10.4). Offset windows are exact for the I1b data volume
// and stable under the operator-triggered writes of the walking skeleton;
// a keyset push-down (WHERE (priority, created_at, id) > cursor) can replace
// this encoding without changing the port, the cursor stays opaque.
type pageCursor struct {
	Offset int `json:"offset"`
}

func encodeCursor(offset int) string {
	b, err := json.Marshal(pageCursor{Offset: offset})
	if err != nil {
		// A struct of one int cannot fail to marshal.
		panic("application: marshal page cursor: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor decodes the opaque page cursor. op names the calling use case
// so a malformed cursor is reported against it (the same opaque encoding backs
// every cursor-paginated read — ListSignals, ListAssets, ListUsers).
func decodeCursor(op, s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, Validationf(op, "invalid cursor: %v", err)
	}
	var pc pageCursor
	if err := json.Unmarshal(b, &pc); err != nil {
		return 0, Validationf(op, "invalid cursor: %v", err)
	}
	if pc.Offset < 0 {
		return 0, Validationf(op, "invalid cursor: negative offset")
	}
	return pc.Offset, nil
}

// validateSignalFilterEnums checks the signal enum filters shared by the
// working-list read and the frozen export filter (ARCH-001 §4, ARCH-007
// §1.2): an unset filter is open, a set one must be a vocabulary value.
// op names the calling use case so the error is reported against it.
func validateSignalFilterEnums(op string, priority *domain.Priority, status *domain.SignalStatus) error {
	if priority != nil && !priority.Valid() {
		return Validationf(op, "invalid priority filter %q", *priority)
	}
	if status != nil && !status.Valid() {
		return Validationf(op, "invalid status filter %q", *status)
	}
	return nil
}

// ListSignals returns one cursor-paginated page of the working list, sorted
// by priority ascending P1→P4 and then created_at (stable tiebreak id). The
// repository contract returns at most limit+1 rows so the page boundary is
// exact: limit+1 signals mean a further page exists.
func (s *Service) ListSignals(ctx context.Context, in ListSignalsInput) (ListSignalsResult, error) {
	const op = "list_signals"

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return ListSignalsResult{}, err
	}
	// signals.read per the matrix: a role-less user (or one without
	// signals.read) is denied; an `assigned`/`own` grant scopes the query to
	// the principal's owned signals (owner_id = principal.id) — the query
	// path half of the object-scope rule (ARCH-005 §5).
	scope := principal.GrantedScope(domain.PermissionSignalsRead)
	if principal.InternalID != "" && scope == domain.ScopeNone {
		return ListSignalsResult{}, Forbiddenf(op, "principal %q is not permitted %s", principal.InternalID, domain.PermissionSignalsRead)
	}

	limit := in.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	if limit < 0 || limit > maxListLimit {
		return ListSignalsResult{}, Validationf(op, "limit %d outside [1,%d] (0 means the default %d)", in.Limit, maxListLimit, defaultListLimit)
	}
	if err := validateSignalFilterEnums(op, in.Priority, in.Status); err != nil {
		return ListSignalsResult{}, err
	}
	offset, err := decodeCursor(op, in.Cursor)
	if err != nil {
		return ListSignalsResult{}, err
	}

	filter := SignalFilter{Priority: in.Priority, Status: in.Status}
	if principal.InternalID != "" && (scope == domain.ScopeAssigned || scope == domain.ScopeOwn) {
		owner := principal.InternalID
		filter.OwnerID = &owner
	}
	rows, err := s.signals.List(ctx, filter, limit, offset)
	if err != nil {
		return ListSignalsResult{}, err
	}

	res := ListSignalsResult{}
	if len(rows) > limit {
		res.Signals = rows[:limit]
		res.NextCursor = encodeCursor(offset + limit)
	} else {
		res.Signals = rows
	}
	return res, nil
}
