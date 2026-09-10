package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the legal-hold use cases (ARCH-007 §2.1/§2.2, WP-6.05 /
// DEV-116): setting, releasing and listing the documented holds that block the
// deletion and the pseudonymisation of their aggregate (a hold preserves the
// original record as-is, §13.4 step 2). All three are gated on
// retention.manage (Administrator); the mutations require a documented reason
// and are audited. A hold set between the dry-run and the execution is honoured
// by the ExecuteRetention hold re-check.

// CreateLegalHoldInput is the setting command. AggregateType defaults to
// 'risk_signal' (the MVP retention subject). Reason is the documented
// justification (mandatory); AggregateID is the held aggregate.
type CreateLegalHoldInput struct {
	AggregateType string
	AggregateID   string
	Reason        string
	Actor         Actor
	CorrelationID string
}

// ReleaseLegalHoldInput is the release command. Reason is mandatory (the
// release of a hold is a documented act too).
type ReleaseLegalHoldInput struct {
	HoldID        string
	Reason        string
	Actor         Actor
	CorrelationID string
}

// ListLegalHoldsInput is the legal-hold list read. Empty filter fields keep a
// filter open.
type ListLegalHoldsInput struct {
	AggregateType string
	AggregateID   string
	Active        *bool
	Actor         Actor
}

// CreateLegalHold sets one documented legal hold (ARCH-007 §2.1). The flow:
// authorize retention.manage → validate the aggregate id and the mandatory
// reason → in one transaction store the hold and append the
// retention.hold_created audit event. A denial writes nothing and sets no hold.
func (s *Service) CreateLegalHold(ctx context.Context, in CreateLegalHoldInput) (LegalHold, error) {
	const op = "create_legal_hold"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return LegalHold{}, err
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return LegalHold{}, err
	}
	if s.retention == nil {
		return LegalHold{}, InfraError(op, errors.New("retention repository is not wired"))
	}
	if in.AggregateID == "" {
		return LegalHold{}, Validationf(op, "aggregate_id must not be empty")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return LegalHold{}, Validationf(op, "a reason is mandatory")
	}
	aggregateType := in.AggregateType
	if aggregateType == "" {
		aggregateType = AuditAggregateRiskSignal
	}

	now := s.clock.Now()
	correlationID := correlationOrNew(in.CorrelationID)
	var stored LegalHold
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.retention.CreateHold(ctx, tx, HoldRecord{
			AggregateType: aggregateType,
			AggregateID:   in.AggregateID,
			Reason:        in.Reason,
			ActorID:       actor.ID,
			CreatedAt:     now,
		})
		if err != nil {
			return err
		}
		stored = row
		after, err := json.Marshal(legalHoldSnapshot{
			HoldID:        row.ID,
			AggregateType: row.AggregateType,
			AggregateID:   row.AggregateID,
			Reason:        row.Reason,
		})
		if err != nil {
			return InfraError(op, err)
		}
		return s.appendRetentionAudit(ctx, tx, EventTypeRetentionHoldCreated, row.AggregateType, row.AggregateID, actor, correlationID, now, after)
	})
	if err != nil {
		return LegalHold{}, err
	}
	return stored, nil
}

// ReleaseLegalHold releases one hold by its id (ARCH-007 §2.2). The flow:
// authorize retention.manage → validate the hold id and the mandatory reason →
// in one transaction release the hold (set-once) and append the
// retention.hold_released audit event against the held aggregate. Releasing an
// already-released or unknown hold is a not-found/conflict and writes nothing.
func (s *Service) ReleaseLegalHold(ctx context.Context, in ReleaseLegalHoldInput) (LegalHold, error) {
	const op = "release_legal_hold"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return LegalHold{}, err
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return LegalHold{}, err
	}
	if s.retention == nil {
		return LegalHold{}, InfraError(op, errors.New("retention repository is not wired"))
	}
	if in.HoldID == "" {
		return LegalHold{}, Validationf(op, "hold_id must not be empty")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return LegalHold{}, Validationf(op, "a reason is mandatory")
	}

	now := s.clock.Now()
	correlationID := correlationOrNew(in.CorrelationID)
	var released LegalHold
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.retention.ReleaseHold(ctx, tx, in.HoldID, now)
		if err != nil {
			return err
		}
		released = row
		after, err := json.Marshal(legalHoldSnapshot{
			HoldID:        row.ID,
			AggregateType: row.AggregateType,
			AggregateID:   row.AggregateID,
			Reason:        in.Reason,
			ReleasedAt:    row.ReleasedAt.UTC().Format(time.RFC3339),
		})
		if err != nil {
			return InfraError(op, err)
		}
		return s.appendRetentionAudit(ctx, tx, EventTypeRetentionHoldReleased, row.AggregateType, row.AggregateID, actor, correlationID, now, after)
	})
	if err != nil {
		return LegalHold{}, err
	}
	return released, nil
}

// ListLegalHolds returns the holds matching the filter (ARCH-007 §2.1). It is
// gated on retention.manage but is a read: it opens no transaction and writes
// no audit row.
func (s *Service) ListLegalHolds(ctx context.Context, in ListLegalHoldsInput) ([]LegalHold, error) {
	const op = "list_legal_holds"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return nil, err
	}
	if _, err := signalActor(op, in.Actor); err != nil {
		return nil, err
	}
	if s.retention == nil {
		return nil, InfraError(op, errors.New("retention repository is not wired"))
	}
	return s.retention.ListHolds(ctx, HoldFilter{
		AggregateType: in.AggregateType,
		AggregateID:   in.AggregateID,
		Active:        in.Active,
	})
}
