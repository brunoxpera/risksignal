package repo

import (
	"context"
	"math"
	"testing"

	"github.com/xpera/risksignal/internal/application"
)

// TestSignalRepoListRejectsInvalidWindow pins the max_rows guard of List
// (DEV-026): a page window (offset+limit+1) the int32 max_rows column
// cannot hold — a negative offset or limit, an offset near MaxInt whose
// addition would overflow, or a window above int32 max — is a validation
// error before any query runs. The repo has no queries bound — the guard is
// what is under test.
func TestSignalRepoListRejectsInvalidWindow(t *testing.T) {
	r := &SignalRepo{}
	ctx := context.Background()

	tests := []struct {
		name          string
		limit, offset int
	}{
		{"negative offset", 20, -1},
		{"negative limit", -1, 0},
		{"window above int32 max", math.MaxInt32, math.MaxInt32},
		{"offset near MaxInt overflows int64 window", math.MaxInt32, int(^uint(0) >> 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := r.List(ctx, application.SignalFilter{}, tt.limit, tt.offset)
			if err == nil {
				t.Fatalf("List(limit %d, offset %d) accepted, want a validation error", tt.limit, tt.offset)
			}
			if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
				t.Fatalf("List(limit %d, offset %d) error kind = %s, want validation", tt.limit, tt.offset, kind)
			}
		})
	}
}
