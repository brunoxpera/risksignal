package postgres

// Unit tests of the §16.2 database event recorders (ARCH-007 §5, DEV-142):
// the pgx query tracer observes a duration in
// database_query_duration_seconds, and the transaction-error counter counts a
// driver-level failure. Both read the process registry installed with
// SetMetrics; the tests install one and reset it afterwards. The pgx hook is
// exercised through the unexported tracer (no connection needed: the methods
// ignore the connection).

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// withRegistry installs a fresh standard registry for one test and resets the
// data-access recorder afterwards.
func withRegistry(t *testing.T) *metrics.Registry {
	t.Helper()
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	SetMetrics(reg)
	t.Cleanup(func() { SetMetrics(nil) })
	return reg
}

func TestQueryTracerObservesDuration(t *testing.T) {
	reg := withRegistry(t)

	tr := queryTracer{}
	ctx := tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "select 1"})
	time.Sleep(2 * time.Millisecond)
	tr.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})

	var found bool
	for _, s := range reg.Snapshot() {
		if s.Name != metrics.NameDatabaseQueryDuration {
			continue
		}
		found = true
		if s.Kind != metrics.KindSeconds || s.Count != 1 || s.Value <= 0 {
			t.Errorf("query duration sample = %+v, want one positive observation", s)
		}
	}
	if !found {
		t.Fatal("database_query_duration_seconds not recorded by the tracer")
	}
}

func TestQueryTracerWithoutRegistryIsANoOp(t *testing.T) {
	SetMetrics(nil)
	// Must not panic without a registry.
	tr := queryTracer{}
	ctx := tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "select 1"})
	tr.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})
}

func TestIncTransactionErrorCounts(t *testing.T) {
	reg := withRegistry(t)

	IncTransactionError()
	IncTransactionError()

	var got float64
	for _, s := range reg.Snapshot() {
		if s.Name == metrics.NameDatabaseTransactionErrors {
			got = s.Value
		}
	}
	if got != 2 {
		t.Fatalf("database_transaction_errors_total = %v, want 2", got)
	}
}
