package repo

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
)

// TestMatchInsertRejectsOutOfRangeScore pins the int32 guard on the
// matches.score column (DEV-026): a score the column cannot hold is a
// validation error before any query runs, never a silent truncation. The
// repo has no queries bound (nil receiver query set) — the guard is what is
// under test, and it fires first.
func TestMatchInsertRejectsOutOfRangeScore(t *testing.T) {
	r := &MatchRepo{}
	ctx := context.Background()

	for _, score := range []int{int(math.MinInt32) - 1, int(math.MaxInt32) + 1} {
		_, err := r.Insert(ctx, nil, application.MatchRecord{Score: score}, time.Now())
		if err == nil {
			t.Fatalf("Insert with score %d accepted, want a validation error", score)
		}
		if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
			t.Fatalf("Insert with score %d error kind = %s, want validation", score, kind)
		}
	}
}

// TestMatchInsertRejectsOutOfRangeAutoScore pins the int32 guard on the
// matches.auto_score column (DEV-069): an override score the column cannot
// hold is a validation error before any query runs, never a silent
// truncation. The repo has no queries bound (nil query set) — the guard is
// what is under test, and it fires first.
func TestMatchInsertRejectsOutOfRangeAutoScore(t *testing.T) {
	r := &MatchRepo{}
	ctx := context.Background()

	for _, score := range []int{int(math.MinInt32) - 1, int(math.MaxInt32) + 1} {
		auto := score
		rec := application.MatchRecord{
			VulnerabilityID: "00000000-0000-0000-0000-000000000001",
			ComponentID:     "00000000-0000-0000-0000-000000000002",
			AutoScore:       &auto,
		}
		_, err := r.Insert(ctx, nil, rec, time.Now())
		if err == nil {
			t.Fatalf("Insert with auto_score %d accepted, want a validation error", score)
		}
		if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
			t.Fatalf("Insert with auto_score %d error kind = %s, want validation", score, kind)
		}
	}
}
