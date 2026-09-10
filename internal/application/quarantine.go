package application

import (
	"context"
	"encoding/json"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// Audit vocabulary of the quarantine commands (ARCH-002 §4, ch. 13.2
// "Quarantäne-Wiederverarbeitung" is auditable): one aggregate type, one
// event per transition, written atomically with the state change — one
// command, one transaction (ch. 5.1).
const (
	// AuditAggregateQuarantine is the aggregate type of quarantine audit
	// rows.
	AuditAggregateQuarantine = "quarantine"

	// AuditActionQuarantineAcknowledged records new -> acknowledged.
	AuditActionQuarantineAcknowledged = "quarantine.acknowledged"
	// AuditActionQuarantineReprocessed records a failed reprocess attempt
	// (attempts + 1, the row stays retryable).
	AuditActionQuarantineReprocessed = "quarantine.reprocessed"
	// AuditActionQuarantineResolved records the terminal transition of a
	// successful reprocess (-> resolved).
	AuditActionQuarantineResolved = "quarantine.resolved"

	// defaultQuarantineActorID is the I2 audit actor of the quarantine
	// commands: a system principal (ch. 13.2 — user principals arrive with
	// I5a). The WP-2.09 CLI passes the operating principal when it lands.
	defaultQuarantineActorID = "operator"
)

// QuarantineListInput narrows the quarantine working list (ARCH-002 §4,
// ch. 11.3 quarantine list). Nil status and empty SourceID keep the filter
// open; Limit is the required page size.
type QuarantineListInput struct {
	Status   *domain.QuarantineStatus
	SourceID string
	Limit    int
}

// QuarantineAckInput is the QuarantineAck command (new -> acknowledged,
// ARCH-002 §4): the operator review with the note. Actor is the audit
// principal and the acknowledged_by of the row; empty defaults to a system
// actor with the id "operator".
type QuarantineAckInput struct {
	ID    string
	Note  string
	Actor Actor
}

// QuarantineReprocessInput is the QuarantineReprocess command (ARCH-002
// §4): re-run the source's normaliser with the current adapter over the raw
// record the row was isolated from. Adapter is the current implementation
// of the row's source port (the composition root's registry resolves it by
// the source type; WP-2.05+ provide the real adapters).
type QuarantineReprocessInput struct {
	ID      string
	Adapter SourcePort
	Actor   Actor // audit principal; empty defaults to the system "operator"
}

// QuarantineReprocessResult reports the attempt. Resolved is true when the
// pass succeeded and the row left the quarantine (-> resolved, linked to
// the new domain object); false when the offending record still fails to
// normalise — the row's attempts incremented and it stays retryable
// (ARCH-002 §4) — which is not an error: the audit event records it.
type QuarantineReprocessResult struct {
	Quarantine domain.Quarantine // committed state after the attempt
	Resolved   bool
	Records    int // domain records the pass normalised
	Errors     int // records the pass still isolated
}

// QuarantineList returns the quarantine working list, oldest isolation
// first, optionally filtered by status and source (ARCH-002 §4, ch. 11.3).
func (s *Service) QuarantineList(ctx context.Context, in QuarantineListInput) ([]domain.Quarantine, error) {
	const op = "quarantine_list"

	if in.Status != nil && !in.Status.Valid() {
		return nil, Validationf(op, "invalid quarantine status filter %q", *in.Status)
	}
	if in.Limit < 1 {
		return nil, Validationf(op, "limit must be >= 1")
	}
	return s.quarantine.List(ctx, in.Status, in.SourceID, in.Limit)
}

// QuarantineAck records the operator review (new -> acknowledged, ARCH-002
// §4): the state change and its audit event run in one transaction; the SQL
// guard (status = 'new') backs the domain transition, so an already
// reviewed or terminal row is rejected before any write and a concurrent
// state change surfaces as a conflict.
func (s *Service) QuarantineAck(ctx context.Context, in QuarantineAckInput) (domain.Quarantine, error) {
	const op = "quarantine_ack"

	if in.ID == "" {
		return domain.Quarantine{}, Validationf(op, "quarantine id must not be empty")
	}
	actor := quarantineActor(in.Actor)

	current, err := s.quarantine.GetByID(ctx, in.ID)
	if err != nil {
		return domain.Quarantine{}, err
	}
	// Domain transition guard (the SQL guard is the persistence backstop):
	// only a new record can be acknowledged.
	if _, err := current.Acknowledge(actor.ID, in.Note); err != nil {
		return domain.Quarantine{}, ValidationError(op, err)
	}

	now := s.clock.Now()
	var updated domain.Quarantine
	if err := s.runTx(ctx, func(tx Tx) error {
		row, err := s.quarantine.Acknowledge(ctx, tx, in.ID, actor.ID, in.Note, now)
		if err != nil {
			return err
		}
		updated = row
		return s.appendQuarantineAudit(ctx, tx, AuditActionQuarantineAcknowledged, current, updated, actor, now)
	}); err != nil {
		return domain.Quarantine{}, err
	}
	return updated, nil
}

// QuarantineReprocess re-runs the source's normaliser over the raw record a
// quarantined row was isolated from (ARCH-002 §4): the pass streams through
// the persistence sink — still-failing records of the document are isolated
// again — and the row's transition, its audit event and the pass writes all
// commit in one transaction.
//
// Outcomes: a clean pass (no isolated record) resolves the row
// (-> resolved, linked to the new domain object of a single-record pass);
// a pass that still isolates the offending record increments attempts and
// stays retryable (new | acknowledged | ready_for_retry -> attempts + 1) —
// never an error, the audit event records it; an acknowledged row is first
// moved to the retryable state inside the same command. An infrastructure
// failure of the pass rolls everything back and surfaces as the returned
// error without a state change.
func (s *Service) QuarantineReprocess(ctx context.Context, in QuarantineReprocessInput) (QuarantineReprocessResult, error) {
	const op = "quarantine_reprocess"

	if in.Adapter == nil {
		return QuarantineReprocessResult{}, Validationf(op, "adapter must not be nil")
	}
	if in.ID == "" {
		return QuarantineReprocessResult{}, Validationf(op, "quarantine id must not be empty")
	}
	actor := quarantineActor(in.Actor)
	now := s.clock.Now()

	current, err := s.quarantine.GetByID(ctx, in.ID)
	if err != nil {
		return QuarantineReprocessResult{}, err
	}
	switch current.Status {
	case domain.QuarantineStatusNew, domain.QuarantineStatusAcknowledged, domain.QuarantineStatusReadyForRetry:
		// retryable entries of the machine
	case domain.QuarantineStatusResolved:
		return QuarantineReprocessResult{}, Validationf(op, "quarantine %s is resolved (terminal)", current.ID)
	default:
		return QuarantineReprocessResult{}, Validationf(op, "quarantine %s has unknown status %q", current.ID, current.Status)
	}
	if current.RawRecordID == "" {
		return QuarantineReprocessResult{}, Validationf(op, "quarantine %s is not attributed to a raw record and cannot be reprocessed", current.ID)
	}
	rawRec, err := s.raws.GetByID(ctx, current.RawRecordID)
	if err != nil {
		return QuarantineReprocessResult{}, err
	}
	desc, err := s.sources.GetByID(ctx, current.SourceID)
	if err != nil {
		return QuarantineReprocessResult{}, err
	}
	if in.Adapter.Type() != desc.Type {
		return QuarantineReprocessResult{}, Validationf(op, "adapter type %q does not match source %s (type %q)", in.Adapter.Type(), current.SourceID, desc.Type)
	}

	result := QuarantineReprocessResult{}
	err = s.runTx(ctx, func(tx Tx) error {
		// An acknowledged row must first be moved to the retryable state
		// (acknowledged -> ready_for_retry, ARCH-002 §4) — same command,
		// same transaction as the attempt and its audit event.
		if current.Status == domain.QuarantineStatusAcknowledged {
			if _, err := s.quarantine.MarkReadyForRetry(ctx, tx, current.ID, now); err != nil {
				return err
			}
		}

		sink := newNormalizeSink(s, tx, current.SourceID, "", rawRec.ID, now)
		pass, err := in.Adapter.Normalize(ctx, NormalizeInput{
			RawRecordID: rawRec.ID,
			Payload:     rawRec.Payload,
			ContentHash: rawRec.ContentHash,
			Meta:        metaForRawRecord(rawRec),
		}, sink)
		if err != nil {
			// Infrastructure failure of the pass: roll back — no partial
			// domain objects, no state change — and surface the cause; the
			// attempt is not counted as a record-level failure.
			return err
		}
		result.Records, result.Errors = pass.Records, pass.Errors

		if pass.Errors > 0 {
			// The offending record still fails to normalise: attempts + 1,
			// the row stays retryable (ARCH-002 §4).
			updated, err := s.quarantine.IncrementAttempts(ctx, tx, current.ID, now)
			if err != nil {
				return err
			}
			result.Quarantine = updated
			return s.appendQuarantineAudit(ctx, tx, AuditActionQuarantineReprocessed, current, updated, actor, now)
		}

		// Clean pass: resolve, linking the new domain object a
		// single-record pass materialised (ARCH-002 §4 resolved_* links;
		// multi-record passes resolve with the outcome note) — the
		// vulnerability through the sink's single-upsert link and the new
		// evidence through the AddEvidence id return (ARCH-003 §7, DEV-053).
		updated, err := s.quarantine.MarkResolved(ctx, tx, current.ID, sink.singleVulnID(), sink.singleEvidenceID(), "reprocessed: normalised ok", now)
		if err != nil {
			return err
		}
		result.Quarantine = updated
		result.Resolved = true
		return s.appendQuarantineAudit(ctx, tx, AuditActionQuarantineResolved, current, updated, actor, now)
	})
	if err != nil {
		return QuarantineReprocessResult{}, err
	}
	return result, nil
}

// appendQuarantineAudit appends the audit event of one quarantine
// transition on the caller's transaction — atomic with the state change
// (ch. 5.1, ch. 13.2). The before/after snapshots are minimised state
// snapshots (ch. 13.5): status and attempts only — no payload bytes, no
// secrets (the reason of an isolation never carries one by contract). The
// row carries no correlation id: a quarantine command writes no outbox row.
func (s *Service) appendQuarantineAudit(ctx context.Context, tx Tx, action string, before, after domain.Quarantine, actor Actor, now time.Time) error {
	return s.audit.Append(ctx, tx, AuditEvent{
		AggregateType:    AuditAggregateQuarantine,
		AggregateID:      before.ID,
		ActorType:        actor.Type,
		ActorID:          actor.ID,
		ActorDisplayName: actor.DisplayName,
		Action:           action,
		OccurredAt:       now,
		Before:           quarantineSnapshot(before),
		After:            quarantineSnapshot(after),
		CorrelationID:    "",
	})
}

// quarantineSnapshot is the minimised before/after state snapshot of a
// quarantine transition (ch. 13.5): the status and the attempt counter.
func quarantineSnapshot(q domain.Quarantine) json.RawMessage {
	b, err := json.Marshal(struct {
		Status   domain.QuarantineStatus `json:"status"`
		Attempts int                     `json:"attempts"`
	}{Status: q.Status, Attempts: q.Attempts})
	if err != nil {
		return nil // two plain fields never fail to marshal
	}
	return b
}

// quarantineActor defaults an empty actor to the I2 system principal of the
// quarantine commands.
func quarantineActor(a Actor) Actor {
	if a.Type == "" {
		a.Type = ActorTypeSystem
	}
	if a.ID == "" {
		a.ID = defaultQuarantineActorID
	}
	return a
}
