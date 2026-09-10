package repo

import (
	"context"
	"math"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
)

// TestListComponentsPageRejectsOutOfRangeLimit pins the int32 guard on the
// components.page_limit query parameter (DEV-069): a limit the int32
// parameter cannot hold is a validation error before any query runs, never a
// silent truncation. The repo has no queries bound (nil query set) — the
// guard is what is under test, and it fires first.
func TestListComponentsPageRejectsOutOfRangeLimit(t *testing.T) {
	r := &ComponentRepo{}
	ctx := context.Background()

	for _, limit := range []int{-1, int(math.MaxInt32) + 1} {
		_, err := r.ListComponentsPage(ctx, "", limit)
		if err == nil {
			t.Fatalf("ListComponentsPage with limit %d accepted, want a validation error", limit)
		}
		if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
			t.Fatalf("ListComponentsPage with limit %d error kind = %s, want validation", limit, kind)
		}
	}
}
