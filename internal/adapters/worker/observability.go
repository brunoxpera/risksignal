package worker

// The worker's §16.2 event-recorded families (implementation concept ch.
// 16.2, ARCH-007 §5, WP-6.08/6.12). The worker records the source run-loop
// completion points (source.go), the outbox relay dispatch points (relay.go)
// and the SLA-escalation transitions of the evaluation scheduler (sla.go) on
// the process registry. The families whose value is current state rather than
// an event — the source data age, the due-job backlog age — are sampled by
// internal/adapters/observability instead and are not listed here.

import "github.com/brunoxpera/risksignal/internal/platform/metrics"

// MetricFamilies returns the §16.2 families the worker writes at its event
// points. It is the writer declaration the NFR-010 coverage guard reads
// (DEV-142); every name must correspond to a recording site in this package.
// The slice is a copy.
func MetricFamilies() []string {
	return []string{
		// Source run-loop completion points (source.go).
		metrics.NameSourceRunDuration,
		metrics.NameSourceRecordsTotal,
		metrics.NameSourceErrorsTotal,
		// Outbox relay dispatch points (relay.go).
		metrics.NameJobsQueueDepth,
		metrics.NameJobsAttemptsTotal,
		metrics.NameJobsDeadLettersTotal,
		// SLA-escalation transitions of the evaluation scheduler (sla.go).
		metrics.NameSignalsSLAEscalationsTotal,
	}
}
