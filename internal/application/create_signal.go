package application

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xpera/risksignal/internal/domain"
	"github.com/xpera/risksignal/internal/platform/uuid"
)

// Event and audit vocabulary of the CreateSignal command (ARCH-001 §2).
const (
	// EventTypeSignalCreated is the outbox type discriminator and the audit
	// action of a signal creation (ARCH-001 §1 outbox.type / §2).
	EventTypeSignalCreated = "signal.created"
	// AuditAggregateRiskSignal is the aggregate type of signal audit rows.
	AuditAggregateRiskSignal = "risk_signal"
	// ActorTypeSystem is the I1b audit actor type (ARCH-001 §1
	// audit_events.actor_type); user principals arrive with I5a.
	ActorTypeSystem = "system"
	// outboxDedupePrefix prefixes the command-level dedupe key (ARCH-001 §2:
	// dedupe_key = "signal.created:" + signal_id).
	outboxDedupePrefix = "signal.created:"
)

// Actor is the audit principal of a command (ARCH-001 §1 audit_events:
// actor_type system in I1b, actor_id 'synthetic-source' | 'demo-seed').
type Actor struct {
	// Type must be ActorTypeSystem in I1b; user actors arrive with I5a.
	Type string
	// ID identifies the acting principal, e.g. "synthetic-source" or
	// "demo-seed".
	ID          string
	DisplayName string
}

// CreateSignalInput is the CreateSignal command. The three writes of the
// command — signal, audit event, outbox event — run inside one transaction
// (ch. 5.1, ARCH-001 §2). MatchID must reference an existing match row
// (FK); CveID travels into the outbox payload; Factors carry the ch. 9.3
// inputs (method/confidence consistency, criticality/exposure and the
// cvss/kev/epss evidence values) from which priority and rule_version are
// derived.
type CreateSignalInput struct {
	MatchID string
	CveID   string
	Factors domain.PriorityFactors

	// CorrelationID links the audit row and the outbox row of this command
	// (ARCH-001 §1 audit_events.correlation_id). Empty generates one.
	CorrelationID string

	// Actor is the audit principal of the command.
	Actor Actor
}

// CreateSignalResult carries the stored signal and the command's correlation
// id (task DEV-018: "Return the signal and correlation_id").
type CreateSignalResult struct {
	Signal        domain.RiskSignal
	CorrelationID string
}

// signalCreatedPayload is the ARCH-001 §2 outbox payload shape:
// { event_id, type: "signal.created", signal_id, match_id, cve_id,
// priority, occurred_at, correlation_id }.
//
// event_id is the logical event identity, generated at command time. The
// outbox row itself gets its id from the gen_random_uuid() column default —
// the payload is written before the row id exists — so the relay's delivery
// idempotency stays keyed on the row id it claims (outbox.id, ARCH-001 §2),
// while event_id gives downstream consumers a stable event identity carried
// in the envelope.
type signalCreatedPayload struct {
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	SignalID      string    `json:"signal_id"`
	MatchID       string    `json:"match_id"`
	CveID         string    `json:"cve_id"`
	Priority      string    `json:"priority"`
	OccurredAt    time.Time `json:"occurred_at"`
	CorrelationID string    `json:"correlation_id"`
}

// signalDedupeKey is the command-level outbox idempotency key (ARCH-001 §2:
// dedupe_key = "signal.created:" + signal_id), unique for the row lifetime.
func signalDedupeKey(signalID string) string {
	return outboxDedupePrefix + signalID
}

// signalSnapshot is the minimised `after` snapshot of the audit event
// (concept ch. 13.5: minimised state, no secrets). `before` stays NULL for a
// creation.
type signalSnapshot struct {
	ID          string    `json:"id"`
	MatchID     string    `json:"match_id"`
	Priority    string    `json:"priority"`
	Status      string    `json:"status"`
	Version     int       `json:"version"`
	RuleVersion string    `json:"rule_version"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateSignal runs the atomic signal + audit + outbox command (ARCH-001
// §2): inside the injected transaction runner (postgres.WithTx in
// production) it writes the risk signal, appends the audit event and
// appends the outbox event — all three on the same transaction, so either
// all of them commit or none of them does. If the outbox append fails (the
// ARCH-001 §5 fault seam), the error propagates unwrapped and the
// transaction rolls back: no signal-without-event or event-without-signal
// half-state can exist (TR-004).
//
// Validation runs before the transaction; domain-derived values (priority,
// rule version) are derived here from the validated factors exactly as
// domain.NewRiskSignal would. The row id is assigned by the database
// (ch. 7.2 gen_random_uuid(), the insert takes no id) and read back from the
// RETURNING row, which is why the stored aggregate is assembled from the
// repository's result rather than constructed pre-insert.
func (s *Service) CreateSignal(ctx context.Context, in CreateSignalInput) (CreateSignalResult, error) {
	const op = "create_signal"

	if in.MatchID == "" {
		return CreateSignalResult{}, Validationf(op, "match_id must not be empty")
	}
	if in.CveID == "" {
		return CreateSignalResult{}, Validationf(op, "cve_id must not be empty")
	}
	if in.Actor.Type != ActorTypeSystem {
		return CreateSignalResult{}, Validationf(op, "actor type %q not allowed in I1b (only %q)", in.Actor.Type, ActorTypeSystem)
	}
	if in.Actor.ID == "" {
		return CreateSignalResult{}, Validationf(op, "actor id must not be empty")
	}
	if err := in.Factors.Validate(); err != nil {
		return CreateSignalResult{}, ValidationError(op, err)
	}

	correlationID := in.CorrelationID
	if correlationID == "" {
		correlationID = uuid.New()
	}

	record := SignalRecord{
		MatchID:     in.MatchID,
		Priority:    domain.ComputePriority(in.Factors),
		RuleVersion: domain.PriorityRuleVersion,
		Factors:     in.Factors,
	}

	var result CreateSignalResult
	err := s.runTx(ctx, func(tx Tx) error {
		now := s.clock.Now()

		// 1) state change
		created, err := s.signals.Create(ctx, tx, record, now)
		if err != nil {
			return err
		}

		// 2) audit event (append-only, same transaction)
		after, err := json.Marshal(signalSnapshot{
			ID:          created.ID,
			MatchID:     created.MatchID,
			Priority:    string(created.Priority),
			Status:      string(created.Status),
			Version:     created.Version,
			RuleVersion: created.RuleVersion,
			CreatedAt:   now,
		})
		if err != nil {
			return InfraError(op, err)
		}
		audit := AuditEvent{
			AggregateType:    AuditAggregateRiskSignal,
			AggregateID:      created.ID,
			ActorType:        in.Actor.Type,
			ActorID:          in.Actor.ID,
			ActorDisplayName: in.Actor.DisplayName,
			Action:           EventTypeSignalCreated,
			OccurredAt:       now,
			Before:           nil, // creates have no before state
			After:            after,
			CorrelationID:    correlationID,
		}
		if err := s.audit.Append(ctx, tx, audit); err != nil {
			return err
		}

		// 3) outbox event (same transaction; the §5 fault seam)
		payload, err := json.Marshal(signalCreatedPayload{
			EventID:       uuid.New(),
			Type:          EventTypeSignalCreated,
			SignalID:      created.ID,
			MatchID:       created.MatchID,
			CveID:         in.CveID,
			Priority:      string(created.Priority),
			OccurredAt:    now,
			CorrelationID: correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		ev := OutboxEvent{
			Type:        EventTypeSignalCreated,
			Payload:     payload,
			DedupeKey:   signalDedupeKey(created.ID),
			AvailableAt: now,
			CreatedAt:   now,
		}
		if err := s.outbox.Append(ctx, tx, ev); err != nil {
			return err
		}

		result = CreateSignalResult{Signal: created, CorrelationID: correlationID}
		return nil
	})
	if err != nil {
		return CreateSignalResult{}, err
	}
	return result, nil
}
