package metrics

// The canonical §16.2 metric families (implementation concept ch. 16.2,
// ARCH-007 §5, WP-6.08 / DEV-120). RegisterStandard declares every family on
// a registry at startup, so the Prometheus exposition rendered by
// Registry.Prometheus is complete — HELP/TYPE lines present — even before the
// first observation. The name and help strings are the single source of the
// exposition vocabulary; the recorders (the httpapi middleware, the worker
// source jobs and the outbox relay) reference the same constants so a family
// can never be re-declared with a drifting help text.
const (
	// HTTP request metrics (recorded by the httpapi metrics middleware,
	// httpapi.MetricsMiddleware).
	NameHTTPRequestsTotal     = "http_requests_total"
	NameHTTPRequestDuration   = "http_request_duration_seconds"
	NameHTTPResponsesByStatus = "http_responses_by_status_total"
	NameHTTPInflight          = "http_inflight"

	// Source run-loop metrics (recorded by the worker source jobs,
	// internal/adapters/worker/source.go).
	NameSourceRunDuration  = "source_run_duration_seconds"
	NameSourceRecordsTotal = "source_records_total"
	NameSourceErrorsTotal  = "source_errors_total"
	NameSourceDataAge      = "source_data_age_seconds"

	// Job/outbox metrics (recorded by the worker outbox relay).
	NameJobsQueueDepth       = "jobs_queue_depth"
	NameJobsOldestAge        = "jobs_oldest_age_seconds"
	NameJobsAttemptsTotal    = "jobs_attempts_total"
	NameJobsDeadLettersTotal = "jobs_dead_letters_total"

	// Signal-state metrics.
	NameSignalsOpenByPriority   = "signals_open_by_priority"
	NameSignalsSLARemaining     = "signals_sla_remaining_seconds"
	NameSignalsSLABreachesTotal = "signals_sla_breaches_total"
	NameSignalsUnassigned       = "signals_unassigned"

	// Database metrics.
	NameDatabaseConnections       = "database_connections"
	NameDatabaseQueryDuration     = "database_query_duration_seconds"
	NameDatabaseTransactionErrors = "database_transaction_errors_total"
	NameDatabaseSizeBytes         = "database_size_bytes"

	// Notification metrics.
	NameNotificationsDeliveries = "notifications_deliveries_total"
	NameNotificationsFailures   = "notifications_failures_total"
	NameNotificationsRetryAge   = "notifications_retry_age_seconds"
)

// The canonical help texts of the §16.2 families (same lockstep rule as the
// names above).
const (
	HelpHTTPRequestsTotal         = "HTTP requests served, by method and path"
	HelpHTTPRequestDuration       = "duration of one served HTTP request in seconds"
	HelpHTTPResponsesByStatus     = "HTTP responses by status class, by method and status"
	HelpHTTPInflight              = "HTTP requests currently being served"
	HelpSourceRunDuration         = "duration of one completed source run pass"
	HelpSourceRecordsTotal        = "raw documents the source's fetch passes stored in this process"
	HelpSourceErrorsTotal         = "records the source's normalize passes isolated in this process"
	HelpSourceDataAge             = "age in seconds of the newest record of the source"
	HelpJobsQueueDepth            = "outbox jobs claimed in the most recent relay drain"
	HelpJobsOldestAge             = "age in seconds of the oldest due outbox job"
	HelpJobsAttemptsTotal         = "outbox delivery attempts made in this process"
	HelpJobsDeadLettersTotal      = "outbox jobs dead-lettered in this process"
	HelpSignalsOpenByPriority     = "open signals by priority"
	HelpSignalsSLARemaining       = "remaining seconds of the tightest open SLA clock of the signal"
	HelpSignalsSLABreachesTotal   = "SLA breaches recorded in this process"
	HelpSignalsUnassigned         = "open signals without an owner"
	HelpDatabaseConnections       = "database connections held by the pool"
	HelpDatabaseQueryDuration     = "duration of one database query in seconds"
	HelpDatabaseTransactionErrors = "database transaction errors in this process"
	HelpDatabaseSizeBytes         = "size of the database in bytes"
	HelpNotificationsDeliveries   = "notifications delivered in this process"
	HelpNotificationsFailures     = "notification delivery failures in this process"
	HelpNotificationsRetryAge     = "age in seconds of the oldest pending notification retry"
)

// RegisterStandard declares every §16.2 family on r. It is idempotent (a
// re-declaration with the same kind and help is a no-op) and must be called
// before any recorder writes, so the family kinds are fixed by the canonical
// vocabulary rather than by the first write. RegisterStandard is the single
// call the composition roots make; the exposition then renders the complete
// family set.
func RegisterStandard(r *Registry) {
	if r == nil {
		return
	}
	r.Counter(NameHTTPRequestsTotal, HelpHTTPRequestsTotal)
	r.Seconds(NameHTTPRequestDuration, HelpHTTPRequestDuration)
	r.Counter(NameHTTPResponsesByStatus, HelpHTTPResponsesByStatus)
	r.Gauge(NameHTTPInflight, HelpHTTPInflight)

	r.Seconds(NameSourceRunDuration, HelpSourceRunDuration)
	r.Counter(NameSourceRecordsTotal, HelpSourceRecordsTotal)
	r.Counter(NameSourceErrorsTotal, HelpSourceErrorsTotal)
	r.Gauge(NameSourceDataAge, HelpSourceDataAge)

	r.Gauge(NameJobsQueueDepth, HelpJobsQueueDepth)
	r.Gauge(NameJobsOldestAge, HelpJobsOldestAge)
	r.Counter(NameJobsAttemptsTotal, HelpJobsAttemptsTotal)
	r.Counter(NameJobsDeadLettersTotal, HelpJobsDeadLettersTotal)

	r.Gauge(NameSignalsOpenByPriority, HelpSignalsOpenByPriority)
	r.Gauge(NameSignalsSLARemaining, HelpSignalsSLARemaining)
	r.Counter(NameSignalsSLABreachesTotal, HelpSignalsSLABreachesTotal)
	r.Gauge(NameSignalsUnassigned, HelpSignalsUnassigned)

	r.Gauge(NameDatabaseConnections, HelpDatabaseConnections)
	r.Seconds(NameDatabaseQueryDuration, HelpDatabaseQueryDuration)
	r.Counter(NameDatabaseTransactionErrors, HelpDatabaseTransactionErrors)
	r.Gauge(NameDatabaseSizeBytes, HelpDatabaseSizeBytes)

	r.Counter(NameNotificationsDeliveries, HelpNotificationsDeliveries)
	r.Counter(NameNotificationsFailures, HelpNotificationsFailures)
	r.Gauge(NameNotificationsRetryAge, HelpNotificationsRetryAge)
}
