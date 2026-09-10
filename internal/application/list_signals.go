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
// the default (20); limits above maxListLimit are rejected.
type ListSignalsInput struct {
	Limit    int
	Cursor   string
	Priority *domain.Priority
	Status   *domain.SignalStatus
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

func decodeCursor(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, Validationf("list_signals", "invalid cursor: %v", err)
	}
	var pc pageCursor
	if err := json.Unmarshal(b, &pc); err != nil {
		return 0, Validationf("list_signals", "invalid cursor: %v", err)
	}
	if pc.Offset < 0 {
		return 0, Validationf("list_signals", "invalid cursor: negative offset")
	}
	return pc.Offset, nil
}

// ListSignals returns one cursor-paginated page of the working list, sorted
// by priority ascending P1→P4 and then created_at (stable tiebreak id). The
// repository contract returns at most limit+1 rows so the page boundary is
// exact: limit+1 signals mean a further page exists.
func (s *Service) ListSignals(ctx context.Context, in ListSignalsInput) (ListSignalsResult, error) {
	const op = "list_signals"

	limit := in.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	if limit < 0 || limit > maxListLimit {
		return ListSignalsResult{}, Validationf(op, "limit %d outside [1,%d] (0 means the default %d)", in.Limit, maxListLimit, defaultListLimit)
	}
	if in.Priority != nil && !in.Priority.Valid() {
		return ListSignalsResult{}, Validationf(op, "invalid priority filter %q", *in.Priority)
	}
	if in.Status != nil && !in.Status.Valid() {
		return ListSignalsResult{}, Validationf(op, "invalid status filter %q", *in.Status)
	}
	offset, err := decodeCursor(in.Cursor)
	if err != nil {
		return ListSignalsResult{}, err
	}

	rows, err := s.signals.List(ctx, SignalFilter{Priority: in.Priority, Status: in.Status}, limit, offset)
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
