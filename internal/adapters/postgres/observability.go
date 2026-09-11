package postgres

// The database §16.2 event recorders (implementation concept ch. 16.2,
// ARCH-007 §5, WP-6.08/6.12 follow-up / DEV-142). Two database families have
// an event path rather than a periodic sample and are recorded here, at the
// data-access home:
//
//	database_query_duration_seconds — observed by the pgx query tracer on
//	every query (the pgx query/trace hook), so the pool's own connections
//	report their latency.
//	database_transaction_errors_total — counted by the adapter error mapping
//	(repo.mapDBError) when it surfaces a driver-level failure, and by the
//	transaction boundary (WithTx) when a begin/commit fails.
//
// The registry is a process singleton installed once at the composition root
// (SetMetrics) beside the pool construction. It is stored behind an atomic
// pointer so the connection tracers — which run on the pool's own
// goroutines — read it race-free; it is written before the pool serves any
// query and is read-only afterwards. A nil registry (the tests and the
// composition roots that do not expose /metrics) makes every recorder a
// no-op.

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// registry is the process registry the data-access layer records its §16.2
// database families on. See SetMetrics.
var registry atomic.Pointer[metrics.Registry]

// SetMetrics installs the process metrics registry the data-access layer
// records on (ARCH-007 §5). It is called once at the composition root, beside
// the pool construction, before any query runs; a nil registry disables the
// recording. Because a pgx tracer observes the pool's own connections, the
// registry is process-scoped rather than passed to every repository.
func SetMetrics(reg *metrics.Registry) { registry.Store(reg) }

// observeQueryDuration records one query duration observation on the wired
// registry. It is a no-op without a registry.
func observeQueryDuration(seconds float64) {
	if reg := registry.Load(); reg != nil {
		reg.Seconds(metrics.NameDatabaseQueryDuration, metrics.HelpDatabaseQueryDuration).Observe(seconds)
	}
}

// IncTransactionError increments database_transaction_errors_total on the
// wired registry: the adapter surfaces a driver-level database failure the
// error mapping could not classify as an expected (validation/conflict/
// not-found) outcome. It is a no-op without a registry. It is exported so the
// repository error mapping (repo.mapDBError) and the transaction boundary
// (WithTx) record through the same family.
func IncTransactionError() {
	if reg := registry.Load(); reg != nil {
		reg.Counter(metrics.NameDatabaseTransactionErrors, metrics.HelpDatabaseTransactionErrors).Inc()
	}
}

// queryTracer is the pgx QueryTracer of the pool (the pgx query/trace hook of
// DEV-142): it observes the wall-clock duration of every Query/QueryRow/Exec
// on a pool connection in database_query_duration_seconds. It carries no
// state — the start instant travels in the query context — so one value
// serves every connection.
type queryTracer struct{}

// queryStartKey keys the query start instant in the query context. The zero
// struct is a unique, unexported key.
type queryStartKey struct{}

// TraceQueryStart stamps the query start instant into the context.
func (queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, queryStartKey{}, time.Now())
}

// TraceQueryEnd observes the elapsed duration of the finished query. A query
// whose start instant is missing (a tracer misconfiguration) is not observed.
func (queryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if start, ok := ctx.Value(queryStartKey{}).(time.Time); ok {
		observeQueryDuration(time.Since(start).Seconds())
	}
}

// compile-time proof the tracer satisfies the pgx hook.
var _ pgx.QueryTracer = queryTracer{}

// MetricFamilies returns the §16.2 families the data-access layer records at
// its event points: the query duration (the pgx query tracer) and the
// driver-level transaction errors (the adapter error mapping and the
// transaction boundary). It is the writer declaration the NFR-010 coverage
// guard reads (DEV-142). The slice is a copy.
func MetricFamilies() []string {
	return []string{
		metrics.NameDatabaseQueryDuration,
		metrics.NameDatabaseTransactionErrors,
	}
}
