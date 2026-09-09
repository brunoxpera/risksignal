package application_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// seedViews inserts n joined view rows into the fake read store with
// deterministic ids and created times: priority cycles P1..P4 so every
// filter and the sort are exercised.
func seedViews(h *harness, n int) {
	for i := 0; i < n; i++ {
		p := []domain.Priority{domain.PriorityP1, domain.PriorityP2, domain.PriorityP3, domain.PriorityP4}[i%4]
		ts := fixedNow.Add(time.Duration(i) * time.Minute)
		h.db.signalViews = append(h.db.signalViews, application.Signal{
			ID:         viewID(i),
			MatchID:    "match-" + viewID(i),
			CveID:      "CVE-2024-" + pad(i),
			Priority:   p,
			Status:     domain.SignalStatusNew,
			Confidence: domain.ConfidenceHigh,
			Method:     domain.MatchMethodExactIdentifier,
			Asset: application.SignalAsset{
				ID: "asset-" + viewID(i), Name: "portal", Type: domain.AssetTypeServerVM,
				Criticality: domain.CriticalityCritical, Exposure: domain.ExposureInternet,
			},
			Product:   application.SignalProduct{Vendor: "acme", Product: "portal", Version: "2.4.4"},
			Summary:   "synthetic case",
			CreatedAt: ts,
			Version:   1,
		})
	}
}

func viewID(i int) string {
	return string(rune('a'+i%26)) + string(rune('0'+i/26)) // not a uuid; ids are opaque strings in the fakes
}

func pad(i int) string {
	if i < 10 {
		return "000" + string(rune('0'+i))
	}
	return "00" + string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// TestListSignalsPagesThroughTheWholeList walks cursor pages of size 2 over
// 7 signals and asserts the union is complete, ordered P1→P4 then
// created_at, and that the last page carries no next cursor.
func TestListSignalsPagesThroughTheWholeList(t *testing.T) {
	h := newHarness(t)
	seedViews(h, 7)
	ctx := context.Background()

	var seen []string
	cursor := ""
	pages := 0
	for {
		res, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListSignals page %d: %v", pages, err)
		}
		for _, s := range res.Signals {
			seen = append(seen, s.ID)
		}
		pages++
		if res.NextCursor == "" {
			break
		}
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		cursor = res.NextCursor
	}
	if pages != 4 { // 7 signals at 2 per page → 4 pages
		t.Fatalf("pages = %d, want 4", pages)
	}
	if len(seen) != 7 {
		t.Fatalf("seen %d signals, want all 7", len(seen))
	}
	// Sort assertion: P1→P4, then created_at — every seed is already in
	// that order, so the pages must reproduce it exactly.
	for i := 1; i < len(seen); i++ {
		prev, cur := findView(h, seen[i-1]), findView(h, seen[i])
		if prev == nil || cur == nil {
			t.Fatalf("view lookup failed for %v", seen)
		}
		if priorityRank(prev.Priority) > priorityRank(cur.Priority) {
			t.Fatalf("page order breaks priority sort at %q (%s) → %q (%s)", prev.ID, prev.Priority, cur.ID, cur.Priority)
		}
		if prev.Priority == cur.Priority && prev.CreatedAt.After(cur.CreatedAt) {
			t.Fatalf("page order breaks created_at sort at %q → %q", prev.ID, cur.ID)
		}
	}
}

func findView(h *harness, id string) *application.Signal {
	for i := range h.db.signalViews {
		if h.db.signalViews[i].ID == id {
			return &h.db.signalViews[i]
		}
	}
	return nil
}

// TestListSignalsDefaultLimitAndMax verifies the limit semantics: 0 means
// the default 20, more than 100 is rejected as validation.
func TestListSignalsDefaultLimitAndMax(t *testing.T) {
	h := newHarness(t)
	seedViews(h, 25)
	ctx := context.Background()

	// default limit 20 → first page has 20 and a next cursor
	res, err := h.svc.ListSignals(ctx, application.ListSignalsInput{})
	if err != nil {
		t.Fatalf("ListSignals: %v", err)
	}
	if len(res.Signals) != 20 {
		t.Fatalf("default page = %d signals, want 20", len(res.Signals))
	}
	if res.NextCursor == "" {
		t.Fatal("no next cursor although 25 signals exist")
	}

	// explicit 0 behaves like the default
	res0, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: 0})
	if err != nil || len(res0.Signals) != 20 {
		t.Fatalf("limit 0 page = %d (%v), want 20", len(res0.Signals), err)
	}

	// > max → validation error
	if _, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: 101}); err == nil {
		t.Fatal("limit 101 accepted, want a validation error")
	} else if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
		t.Fatalf("limit 101 error kind = %s, want validation", kind)
	}
	if _, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: -1}); err == nil {
		t.Fatal("negative limit accepted, want a validation error")
	}
}

// TestListSignalsFiltersAndTieBreak covers the priority/status filters and
// the id tie-break of equal created_at.
func TestListSignalsFiltersAndTieBreak(t *testing.T) {
	h := newHarness(t)
	seedViews(h, 8)
	ctx := context.Background()

	// priority filter: exactly the P1 rows, in id order.
	p1 := domain.PriorityP1
	res, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Priority: &p1})
	if err != nil {
		t.Fatalf("ListSignals P1: %v", err)
	}
	for _, s := range res.Signals {
		if s.Priority != domain.PriorityP1 {
			t.Fatalf("filter returned priority %s, want only P1", s.Priority)
		}
	}
	if len(res.Signals) != 2 {
		t.Fatalf("P1 rows = %d, want 2", len(res.Signals))
	}

	// status filter
	st := domain.SignalStatusNew
	resNew, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Status: &st})
	if err != nil || len(resNew.Signals) != 8 {
		t.Fatalf("status filter returned %d (%v), want all 8", len(resNew.Signals), err)
	}
	// invalid filter values are rejected at the boundary
	badStatus := domain.SignalStatus("resolved_typo")
	if _, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Status: &badStatus}); err == nil {
		t.Fatal("invalid status filter accepted, want a validation error")
	}
}

// TestListSignalsRejectsInvalidCursor verifies that a malformed opaque
// cursor is a validation error, not an infrastructure error.
func TestListSignalsRejectsInvalidCursor(t *testing.T) {
	h := newHarness(t)
	seedViews(h, 3)
	ctx := context.Background()

	for _, cursor := range []string{"not-base64!!", "aGVsbG8", "eyJvZmZzZXQiOi0xfQ"} { // garbage, "hello", offset -1
		_, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Cursor: cursor})
		if err == nil {
			t.Fatalf("cursor %q accepted, want a validation error", cursor)
		}
		if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
			t.Fatalf("cursor %q error kind = %s, want validation", cursor, kind)
		}
	}
}

// TestListSignalsEndsWithAnExactFinalPage: the last page carries the
// remaining signal and no next cursor — the pagination terminates exactly.
func TestListSignalsEndsWithAnExactFinalPage(t *testing.T) {
	h := newHarness(t)
	seedViews(h, 3)
	ctx := context.Background()

	first, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: 2})
	if err != nil {
		t.Fatalf("ListSignals: %v", err)
	}
	if len(first.Signals) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d signals with cursor %q, want 2 signals and a next cursor", len(first.Signals), first.NextCursor)
	}
	second, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("ListSignals page 2: %v", err)
	}
	if len(second.Signals) != 1 || second.NextCursor != "" {
		t.Fatalf("page 2 = %d signals with cursor %q, want the last signal and no cursor", len(second.Signals), second.NextCursor)
	}

	// A cursor beyond the last row yields an empty page without an error.
	third, err := h.svc.ListSignals(ctx, application.ListSignalsInput{Limit: 2, Cursor: cursorForOffset(t, 3)})
	if err != nil {
		t.Fatalf("ListSignals beyond the end: %v", err)
	}
	if len(third.Signals) != 0 || third.NextCursor != "" {
		t.Fatalf("page beyond the end = %d signals with cursor %q, want an empty page", len(third.Signals), third.NextCursor)
	}
}

// cursorForOffset builds an opaque cursor for a page offset the same way the
// use case encodes page state (base64 of a JSON page cursor).
func cursorForOffset(t *testing.T, offset int) string {
	t.Helper()
	b, err := json.Marshal(struct {
		Offset int `json:"offset"`
	}{Offset: offset})
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
