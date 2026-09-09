package application

// Outbox vocabulary of the source.run job types (ARCH-002 §5, ch. 14.1):
// the event type discriminators, the job payload shapes and the dedupe key
// builders of the source.fetch and source.normalize jobs the worker relay
// dispatches on (WP-2.08 registers the handlers in
// internal/adapters/worker; this file is the single source of the job
// contract both sides share).
//
// Every payload carries identities only — source ids, raw record ids and
// timestamps — never a secret: the API-key reference is resolved by the
// fetching adapter at fetch time and never persisted (ch. 3.3, TR-013). The
// dedupe keys make the outbox UQ (dedupe_key) idempotent at the schema
// level: re-enqueuing a job that is already queued — or was already
// delivered — is a conflict the enqueuers treat as a no-op (ADR-012
// consequence).

import "time"

// Event type discriminators of the source jobs (ARCH-002 §5). The relay
// registry keys its handlers by these values; EventTypeSourceNormalize is
// the type of the job a successful fetch enqueues (fetch_source.go).
const (
	// EventTypeSourceFetch is the outbox type of the source.fetch job: one
	// fetch half of one source run (ARCH-002 §5) — open a run, call the
	// source's Fetch, store the raw record, commit cursor_after and
	// enqueue the source.normalize job of the stored record. Enqueued by
	// the scheduler when a source's schedule is due (dedupe key
	// source_id + plan_time) or by the source run command for a manual run
	// (dedupe key source_id + request_id).
	EventTypeSourceFetch = "source.fetch"

	// EventTypeSourceNormalize is the outbox type of the source.normalize
	// job (declared in fetch_source.go): one normalise half of one stored
	// raw record.
	EventTypeSourceNormalize = "source.normalize"
)

// SourceFetchJobPayload is the outbox payload of a source.fetch job
// (ARCH-002 §5). Exactly one of PlanTime (a scheduled run — the schedule
// slot the job belongs to) or RequestID (a manual run — the operator's
// trigger id) is set; the relay handlers do not branch on it — the fetch
// half is the same — but the dedupe key of the job derives from it
// (ch. 14.1: source_id + plan_time/manual request_id).
type SourceFetchJobPayload struct {
	SourceID  string    `json:"source_id"`
	PlanTime  time.Time `json:"plan_time,omitempty"`  // scheduled run: the due schedule slot
	RequestID string    `json:"request_id,omitempty"` // manual run: the operator trigger id
}

// SourceNormalizeJobPayload is the outbox payload of a source.normalize job
// (ARCH-002 §5): the raw record identity plus the fetch metadata the
// normalise pass receives. It carries no secret: the API key reference is
// resolved by the fetching adapter and never persisted (ch. 3.3, TR-013).
type SourceNormalizeJobPayload struct {
	RawRecordID string    `json:"raw_record_id"`
	SourceID    string    `json:"source_id"`
	FetchedAt   time.Time `json:"fetched_at"`
}

// sourceFetchDedupePrefix and sourceNormalizeDedupePrefix namespace the
// outbox dedupe keys of the two job types, so a raw record id, a plan time
// or a request id can never collide across job types or enqueue paths.
const (
	sourceFetchDedupePrefix     = "source.fetch:"
	sourceNormalizeDedupePrefix = "source.normalize:"
)

// sourceFetchPlanDedupeKey is the dedupe key of one scheduled source.fetch
// job (ch. 14.1, ARCH-002 §5): source_id + plan_time — one job per schedule
// slot, so the scheduler's repeated cycles can never enqueue the same slot
// twice (the outbox UQ turns a re-enqueue into a no-op) and a job once
// delivered for a slot stays delivered. planTime is canonicalised to UTC
// RFC 3339 second precision — schedule slots are hour/day boundaries, so
// the format loses nothing.
func sourceFetchPlanDedupeKey(sourceID string, planTime time.Time) string {
	return sourceFetchDedupePrefix + "plan:" + sourceID + ":" + planTime.UTC().Format(time.RFC3339)
}

// sourceFetchManualDedupeKey is the dedupe key of one manual source.fetch
// job (ch. 14.1, ARCH-002 §5): source_id + request_id. A repeated manual
// trigger with the same request id is a no-op; a fresh request id always
// enqueues a fresh job, bypassing the schedule.
func sourceFetchManualDedupeKey(sourceID, requestID string) string {
	return sourceFetchDedupePrefix + "manual:" + sourceID + ":" + requestID
}

// sourceNormalizeDedupeKey is the dedupe key of one source.normalize job
// (ch. 14.1, ARCH-002 §1/§5): raw_record_id + normalizer_version — one
// normalise job per stored raw record per adapter normaliser version. The
// version comes from the adapter that produced the record's fetch
// (SourcePort.NormalizerVersion); bumping it forces a fresh normalise pass
// without dedupe (the mechanism behind the quarantine ready_for_retry
// reprocess).
func sourceNormalizeDedupeKey(rawRecordID, normalizerVersion string) string {
	return sourceNormalizeDedupePrefix + rawRecordID + ":" + normalizerVersion
}
