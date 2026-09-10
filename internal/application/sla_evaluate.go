package application

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// This file owns the sla.evaluate use case of ARCH-004 §4.4 (WP-4.05 /
// DEV-080): the breach evaluation the worker scheduler drives on its minute
// cadence. It scans the open acknowledgement clocks past their effective
// deadline and, per unacknowledged P1 signal, (1) stamps the first escalation
// instant exactly once (MarkEscalated, escalated_at IS NULL) and writes a
// `signal.escalated` outbox event + audit, then (2) after the first escalation
// emits `reminder` outbox events per the configured cadence (audited each
// time). Reminders are gated by the outbox dedupe key, not by table state: the
// cadence is an injected configuration value (ARCH-004 §4.4 — "cadence is
// config, not a table state"). P2/P3/P4 are never escalated; their clocks just
// breach visibly (FR-031).
//
// Every write follows the house shape — one command, one transaction: state
// change, audit event and outbox event commit together (ch. 5.1). The use case
// reads the injected clock (no wall clock) so the accelerated SLA test drives
// it with a FakeClock and no real waiting.

// Event and audit vocabulary of the sla.evaluate use case (ARCH-004 §4.4,
// ch. 13.2 "Eskalation"). Both actions are written by the worker's SLA
// scheduler on the signal aggregate; the reminder's outbox type is the
// notification kind `reminder` of ARCH-004 §6.2.
const (
	// EventTypeSignalEscalated records the first P1 escalation of a signal
	// (the set-once marker + its outbox event, ch. 13.2 "Eskalation").
	EventTypeSignalEscalated = "signal.escalated"
	// EventTypeSignalReminder records a cadence-gated escalation reminder
	// (the notification kind `reminder` of ARCH-004 §6.2).
	EventTypeSignalReminder = "reminder"
	// ActorSLAEvaluator is the system principal of the sla.evaluate scheduler's
	// audit rows (the escalation and its reminders).
	ActorSLAEvaluator = "sla-evaluator"
)

// SlaEvaluateResult reports one sla.evaluate pass: the due acknowledgement
// clocks the scan returned, the signals escalated this pass and the reminders
// emitted.
type SlaEvaluateResult struct {
	Due       int
	Escalated int
	Reminders int
}

// slaEvaluationPayload is the outbox payload of one escalation or reminder
// event (ARCH-004 §4.4): the house envelope plus the signal identity, its
// priority, the breached target and the escalation/reminder detail. It carries
// identities, enums and timestamps only — never free text (ch. 3.3, TR-013).
type slaEvaluationPayload struct {
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	SignalID      string    `json:"signal_id"`
	Priority      string    `json:"priority"`
	Target        string    `json:"target"`
	DeadlineAt    time.Time `json:"deadline_at"`
	EscalatedAt   time.Time `json:"escalated_at,omitempty"`
	ReminderIndex int       `json:"reminder_index,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
	CorrelationID string    `json:"correlation_id"`
}

// EvaluateSla runs one breach evaluation (ARCH-004 §4.4): scan the open
// acknowledgement clocks past their effective deadline and, per unacknowledged
// P1 signal, escalate once and then remind on the configured cadence. It is
// idempotent: a re-run with no new breach escalates nothing and a reminder of
// an already-emitted cadence window is deduped by the outbox key. The scan and
// each signal's write are separate steps (the scan is a pool read, each write
// its own transaction), so a failure on one signal does not roll back the
// already-escalated ones.
func (s *Service) EvaluateSla(ctx context.Context) (SlaEvaluateResult, error) {
	const op = "evaluate_sla"

	due, err := s.slaClocks.Due(ctx)
	if err != nil {
		return SlaEvaluateResult{}, err
	}
	now := s.clock.Now()

	var res SlaEvaluateResult
	for i := range due {
		clock := due[i]
		// Only the acknowledgement clock drives escalation (ARCH-004 §4.4);
		// the other targets breach visibly without an escalation event.
		if clock.Target != domain.SLATargetAcknowledgement {
			continue
		}
		res.Due++

		sig, err := s.signalTriage.GetRiskSignal(ctx, clock.SignalID)
		if err != nil {
			if kind, _ := ErrorKindOf(err); kind == KindNotFound {
				continue // the signal vanished; nothing to escalate
			}
			return SlaEvaluateResult{}, err
		}
		// An unacknowledged P1 has status new and priority P1 (a non-new
		// status was acknowledged or otherwise moved on). P2/P3/P4 never
		// escalate.
		if sig.Priority != domain.PriorityP1 || sig.Status != domain.SignalStatusNew {
			continue
		}
		if sig.EscalatedAt.IsZero() {
			escalated, err := s.escalateSignal(ctx, op, sig, clock, now)
			if err != nil {
				return SlaEvaluateResult{}, err
			}
			if escalated {
				res.Escalated++
			}
			continue
		}
		reminded, err := s.remindEscalatedSignal(ctx, op, sig, clock, now)
		if err != nil {
			return SlaEvaluateResult{}, err
		}
		if reminded {
			res.Reminders++
		}
	}
	return res, nil
}

// escalateSignal stamps the first escalation instant of an unacknowledged P1
// (ARCH-004 §4.4) and, on the transaction where the set-once guard matched,
// writes the `signal.escalated` outbox event and its audit row. A concurrent
// second evaluator wins no row (MarkEscalated returns false) and writes
// nothing — the escalation is exactly-once. It returns whether this call
// escalated.
func (s *Service) escalateSignal(ctx context.Context, op string, sig domain.RiskSignal, clock domain.SlaClock, now time.Time) (bool, error) {
	correlationID := correlationOrNew("")
	escalated := false
	err := s.runTx(ctx, func(tx Tx) error {
		changed, err := s.signalTriage.MarkEscalated(ctx, tx, sig.ID, now)
		if err != nil {
			return err
		}
		if !changed {
			return nil // already escalated (a concurrent evaluator won)
		}
		escalated = true
		after, err := slaEscalationSnapshot(sig, clock, now)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalEscalated, sig.ID, slaEvaluatorActor(), correlationID, now, nil, after); err != nil {
			return err
		}
		payload, err := json.Marshal(slaEvaluationPayload{
			EventID:       uuid.New(),
			Type:          EventTypeSignalEscalated,
			SignalID:      sig.ID,
			Priority:      string(sig.Priority),
			Target:        string(clock.Target),
			DeadlineAt:    clock.EffectiveDeadline(now),
			EscalatedAt:   now,
			OccurredAt:    now,
			CorrelationID: correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		return s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypeSignalEscalated,
			Payload:     payload,
			DedupeKey:   EventTypeSignalEscalated + ":" + sig.ID,
			AvailableAt: now,
			CreatedAt:   now,
		})
	})
	if err != nil {
		return false, err
	}
	return escalated, nil
}

// remindEscalatedSignal emits one reminder for an already-escalated P1 when
// the configured reminder cadence has elapsed since the escalation instant
// (ARCH-004 §4.4). The cadence window is a config value, not table state: the
// event of window n carries the dedupe key `reminder:<signal>:<n>`, so a
// re-run inside the same window appends nothing while the next window appends
// a fresh reminder. The audit row is written only when the outbox row is
// actually appended — a deduped reminder is not audited twice. It returns
// whether this call emitted a reminder.
func (s *Service) remindEscalatedSignal(ctx context.Context, op string, sig domain.RiskSignal, clock domain.SlaClock, now time.Time) (bool, error) {
	cadence := s.slaReminderCadence
	if cadence <= 0 || sig.EscalatedAt.IsZero() {
		return false, nil
	}
	elapsed := now.Sub(sig.EscalatedAt)
	if elapsed < cadence {
		return false, nil // the first cadence window has not elapsed yet
	}
	index := int(elapsed / cadence) // >= 1
	dedupeKey := EventTypeSignalReminder + ":" + sig.ID + ":" + strconv.Itoa(index)
	correlationID := correlationOrNew("")
	emitted := false
	err := s.runTx(ctx, func(tx Tx) error {
		exists, err := s.outbox.ExistsDedupeKey(ctx, tx, dedupeKey)
		if err != nil {
			return err
		}
		if exists {
			return nil // already reminded for this cadence window — exactly once
		}
		after, err := slaReminderSnapshot(sig, clock, index, now)
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.appendSignalAudit(ctx, tx, EventTypeSignalReminder, sig.ID, slaEvaluatorActor(), correlationID, now, nil, after); err != nil {
			return err
		}
		payload, err := json.Marshal(slaEvaluationPayload{
			EventID:       uuid.New(),
			Type:          EventTypeSignalReminder,
			SignalID:      sig.ID,
			Priority:      string(sig.Priority),
			Target:        string(clock.Target),
			DeadlineAt:    clock.EffectiveDeadline(now),
			EscalatedAt:   sig.EscalatedAt,
			ReminderIndex: index,
			OccurredAt:    now,
			CorrelationID: correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		emitted = true
		return s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypeSignalReminder,
			Payload:     payload,
			DedupeKey:   dedupeKey,
			AvailableAt: now,
			CreatedAt:   now,
		})
	})
	if err != nil {
		return false, err
	}
	return emitted, nil
}

// slaEvaluatorActor is the system audit principal of the SLA scheduler.
func slaEvaluatorActor() Actor {
	return Actor{Type: ActorTypeSystem, ID: ActorSLAEvaluator}
}

// slaEscalationSnapshot is the minimised audit snapshot of a first escalation
// (ch. 13.5): the signal identity, its priority/status, the breached target
// and the effective deadline that passed, plus the escalation instant.
func slaEscalationSnapshot(sig domain.RiskSignal, clock domain.SlaClock, now time.Time) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID          string    `json:"id"`
		Status      string    `json:"status"`
		Priority    string    `json:"priority"`
		Target      string    `json:"target"`
		DeadlineAt  time.Time `json:"deadline_at"`
		EscalatedAt time.Time `json:"escalated_at"`
	}{
		ID:          sig.ID,
		Status:      string(sig.Status),
		Priority:    string(sig.Priority),
		Target:      string(clock.Target),
		DeadlineAt:  clock.EffectiveDeadline(now),
		EscalatedAt: now,
	})
}

// slaReminderSnapshot is the minimised audit snapshot of one cadence reminder
// (ch. 13.5): the signal identity, its priority, the escalation instant, the
// cadence window index and the breached target's effective deadline.
func slaReminderSnapshot(sig domain.RiskSignal, clock domain.SlaClock, index int, now time.Time) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID            string    `json:"id"`
		Status        string    `json:"status"`
		Priority      string    `json:"priority"`
		Target        string    `json:"target"`
		DeadlineAt    time.Time `json:"deadline_at"`
		EscalatedAt   time.Time `json:"escalated_at"`
		ReminderIndex int       `json:"reminder_index"`
	}{
		ID:            sig.ID,
		Status:        string(sig.Status),
		Priority:      string(sig.Priority),
		Target:        string(clock.Target),
		DeadlineAt:    clock.EffectiveDeadline(now),
		EscalatedAt:   sig.EscalatedAt,
		ReminderIndex: index,
	})
}
