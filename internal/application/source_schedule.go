package application

// The source run enqueue use cases (WP-2.08, ARCH-002 §5): the scheduler's
// due-source scan and the operator's manual trigger both enqueue
// source.fetch jobs on the outbox; the worker relay then delivers them
// through the source.fetch handler (internal/adapters/worker). Enqueuing
// is the whole job of this layer — the jobs are rows of the transactional
// outbox, appended with the dedupe keys of ch. 14.1 (source_id +
// plan_time for a scheduled run, source_id + request_id for a manual run,
// source_jobs.go) so the outbox UQ (dedupe_key) makes every re-enqueue of
// the same slot or request a no-op.
//
// The scheduler scan (EnqueueDueSourceFetches) runs on the worker's clock
// port: a source whose schedule string parses to one of the supported
// schedule forms ("@hourly", "@daily" — the schedules the I2 adapters
// declare, ARCH-002 §1/§2) is due when its most recent slot boundary has
// passed; the scan enqueues the job of that slot with available_at = the
// scheduled time, so a job enqueued late is claimable immediately and a
// repeated cycle can never enqueue the same slot twice. A schedule string
// that is not supported is an operator-data mistake: the source is skipped
// and reported in the result (the worker logs it) instead of failing the
// whole cycle. The manual trigger (EnqueueManualSourceFetch) bypasses the
// schedule entirely: every fresh request id enqueues a fresh job, due
// immediately.
//
// The payloads and the dedupe keys carry identities only — no secrets
// (ch. 3.3, TR-013).

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Schedule vocabulary of the sources.schedule column (ARCH-002 §1 lists the
// per-type schedules: NVD "@hourly", KEV/EPSS "@daily"). A schedule slot is
// the schedule period's boundary: an hourly schedule is due at the top of
// each hour, a daily schedule at UTC midnight. The constants are the public
// contract of the column — the worker's due-slot scan and the source
// monitor's planned-interval derivation (the stale threshold of ch. 16.4)
// read the same grammar.
const (
	ScheduleHourly = "@hourly"
	ScheduleDaily  = "@daily"
)

// dueScheduleSlot returns the most recent schedule slot at or before now —
// the plan_time of the source.fetch job the scheduler enqueues for the
// schedule (ARCH-002 §5: available_at = the scheduled time) — or ok=false
// when the schedule string is not supported. Slots are computed on the
// UTC day/hour boundaries so they are stable for any clock instant in the
// period: an hourly source is due once per hour, a daily source once per
// UTC day, and a worker that was down over several periods picks up at the
// current slot (the windowed/full-set fetches of the I2 sources make the
// missed periods self-healing, ARCH-002 §2).
func dueScheduleSlot(schedule string, now time.Time) (slot time.Time, ok bool) {
	switch strings.TrimSpace(schedule) {
	case ScheduleHourly:
		return now.UTC().Truncate(time.Hour), true
	case ScheduleDaily:
		return now.UTC().Truncate(24 * time.Hour), true
	}
	return time.Time{}, false
}

// EnqueueDueSourceFetchesResult reports one scheduler scan: the numbers of
// newly enqueued and already-queued jobs plus the source ids whose schedule
// string is not supported (skipped — the caller logs them; they must not
// fail the worker cycle).
type EnqueueDueSourceFetchesResult struct {
	Enqueued      int
	AlreadyQueued int
	Skipped       []string // source ids with an unparsable schedule
}

// EnqueueDueSourceFetches is the scheduler's source scan (ARCH-002 §5): one
// transaction appends the source.fetch job of every enabled scheduled
// source whose current schedule slot is due — the job's available_at is the
// scheduled time (the slot) and its dedupe key is source_id + plan_time, so
// the outbox UQ turns the job of an already-covered slot into a no-op and
// every worker cycle can run this scan without tracking state. A source
// with an unparsable schedule is skipped and reported; the enqueues of the
// other sources still commit.
func (s *Service) EnqueueDueSourceFetches(ctx context.Context) (EnqueueDueSourceFetchesResult, error) {
	rows, err := s.sources.ListEnabledScheduled(ctx)
	if err != nil {
		return EnqueueDueSourceFetchesResult{}, err
	}
	now := s.clock.Now()

	result := EnqueueDueSourceFetchesResult{}
	err = s.runTx(ctx, func(tx Tx) error {
		for _, row := range rows {
			slot, ok := dueScheduleSlot(row.Schedule, now)
			if !ok {
				result.Skipped = append(result.Skipped, row.ID)
				continue
			}
			queued, err := s.appendSourceFetchJob(ctx, tx, SourceFetchJobPayload{SourceID: row.ID, PlanTime: slot}, sourceFetchPlanDedupeKey(row.ID, slot), slot, now)
			if err != nil {
				return err
			}
			if queued {
				result.Enqueued++
			} else {
				result.AlreadyQueued++
			}
		}
		return nil
	})
	if err != nil {
		return EnqueueDueSourceFetchesResult{}, err
	}
	return result, nil
}

// EnqueueManualSourceFetchInput drives the manual trigger (the source run
// command, ARCH-002 §5): run the source now, bypassing its schedule.
// RequestID is the operator's trigger id — the job's dedupe key is
// source_id + request_id, so a repeated trigger with the same request id is
// a no-op and a fresh request id always enqueues a fresh job.
type EnqueueManualSourceFetchInput struct {
	SourceID  string
	RequestID string
}

// EnqueueManualSourceFetchResult reports one manual trigger: the source the
// job was enqueued for and the request/dedupe identity. AlreadyQueued is
// true when a job with the same request id is already in the outbox (the
// trigger was idempotent — no new job).
type EnqueueManualSourceFetchResult struct {
	SourceID      string
	SourceType    SourceType
	RequestID     string
	DedupeKey     string
	AlreadyQueued bool
}

// EnqueueManualSourceFetch enqueues one manual source.fetch job (ARCH-002
// §5): the job is due immediately — available_at is now — and its dedupe
// key (source_id + request_id) makes the trigger idempotent per request id.
// The source row must exist (a validation/not-found failure otherwise);
// neither its schedule nor its enabled state gates a manual run — the
// operator explicitly asked to run it now, whatever the schedule says.
func (s *Service) EnqueueManualSourceFetch(ctx context.Context, in EnqueueManualSourceFetchInput) (EnqueueManualSourceFetchResult, error) {
	const op = "enqueue_manual_source_fetch"

	if in.SourceID == "" {
		return EnqueueManualSourceFetchResult{}, Validationf(op, "source id must not be empty")
	}
	if in.RequestID == "" {
		return EnqueueManualSourceFetchResult{}, Validationf(op, "request id must not be empty")
	}
	desc, err := s.sources.GetByID(ctx, in.SourceID)
	if err != nil {
		return EnqueueManualSourceFetchResult{}, err
	}

	now := s.clock.Now()
	dedupeKey := sourceFetchManualDedupeKey(in.SourceID, in.RequestID)
	result := EnqueueManualSourceFetchResult{
		SourceID:      in.SourceID,
		SourceType:    desc.Type,
		RequestID:     in.RequestID,
		DedupeKey:     dedupeKey,
		AlreadyQueued: false,
	}
	err = s.runTx(ctx, func(tx Tx) error {
		queued, err := s.appendSourceFetchJob(ctx, tx, SourceFetchJobPayload{SourceID: in.SourceID, RequestID: in.RequestID}, dedupeKey, now, now)
		if err != nil {
			return err
		}
		result.AlreadyQueued = !queued
		return nil
	})
	if err != nil {
		return EnqueueManualSourceFetchResult{}, err
	}
	return result, nil
}

// appendSourceFetchJob appends one source.fetch job on the caller's
// transaction and reports whether the append inserted a row. A job that is
// already in the outbox for the dedupe key (queued, claimed or terminal —
// the UQ spans the row's whole lifetime) is a conflict and a no-op here,
// never an error: the outbox is the idempotency backstop of the scheduler
// and the manual trigger alike.
func (s *Service) appendSourceFetchJob(ctx context.Context, tx Tx, payload SourceFetchJobPayload, dedupeKey string, availableAt, createdAt time.Time) (bool, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return false, InfraError("enqueue_source_fetch", err)
	}
	if err := s.outbox.Append(ctx, tx, OutboxEvent{
		Type:        EventTypeSourceFetch,
		Payload:     body,
		DedupeKey:   dedupeKey,
		AvailableAt: availableAt,
		CreatedAt:   createdAt,
	}); err != nil {
		if kind, ok := ErrorKindOf(err); ok && kind == KindConflict {
			return false, nil // the job is already in the outbox for this key
		}
		return false, err
	}
	return true, nil
}
