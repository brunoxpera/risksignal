package repo

// Unit tests of the §16.2 transaction-error counting of the adapter error
// mapping (ARCH-007 §5, DEV-142): an unclassified driver error is counted in
// database_transaction_errors_total, an expected outcome (not-found, conflict,
// validation) is not.

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// transactionErrors reads the current value of the transaction-error counter
// (zero when the family has no series yet).
func transactionErrors(reg *metrics.Registry) float64 {
	for _, s := range reg.Snapshot() {
		if s.Name == metrics.NameDatabaseTransactionErrors {
			return s.Value
		}
	}
	return 0
}

func TestMapDBErrorCountsInfrastructureFailure(t *testing.T) {
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	postgres.SetMetrics(reg)
	t.Cleanup(func() { postgres.SetMetrics(nil) })

	err := mapDBError("test.op", errors.New("connection reset by peer"))
	if kind, _ := application.ErrorKindOf(err); kind != application.KindInfra {
		t.Fatalf("mapped kind = %v, want infrastructure", kind)
	}
	if got := transactionErrors(reg); got != 1 {
		t.Fatalf("database_transaction_errors_total = %v, want 1", got)
	}
}

func TestMapDBErrorDoesNotCountExpectedOutcomes(t *testing.T) {
	reg := metrics.New()
	metrics.RegisterStandard(reg)
	postgres.SetMetrics(reg)
	t.Cleanup(func() { postgres.SetMetrics(nil) })

	// Not-found and the constraint classes are expected outcomes the domain
	// handles; they are not transaction errors.
	_ = mapDBError("test.op", pgx.ErrNoRows)
	_ = mapDBError("test.op", &pgconn.PgError{Code: "23505"}) // unique_violation
	_ = mapDBError("test.op", &pgconn.PgError{Code: "23503"}) // foreign_key_violation
	_ = mapDBError("test.op", &pgconn.PgError{Code: "22P02"}) // invalid input syntax
	if got := transactionErrors(reg); got != 0 {
		t.Fatalf("database_transaction_errors_total = %v, want 0 (only infrastructure failures count)", got)
	}
}
