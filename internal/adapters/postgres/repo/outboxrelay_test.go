package repo

import (
	"context"
	"math"
	"testing"

	"github.com/xpera/risksignal/internal/application"
)

// TestOutboxRelayClaimBatchRejectsInvalidLimit pins the batch-limit guard
// of ClaimBatch (DEV-026): non-positive limits and limits the int32
// batch-size column cannot hold are validation errors before any query
// runs. The repo has no queries bound — the guard is what is under test.
func TestOutboxRelayClaimBatchRejectsInvalidLimit(t *testing.T) {
	r := &OutboxRelay{}
	ctx := context.Background()

	for _, limit := range []int{0, -1, int(math.MaxInt32) + 1} {
		_, err := r.ClaimBatch(ctx, limit)
		if err == nil {
			t.Fatalf("ClaimBatch with limit %d accepted, want a validation error", limit)
		}
		if kind, _ := application.ErrorKindOf(err); kind != application.KindValidation {
			t.Fatalf("ClaimBatch with limit %d error kind = %s, want validation", limit, kind)
		}
	}
}
