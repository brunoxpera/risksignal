package application

import (
	"context"
	"errors"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the retention-report reads (ARCH-007 §2.2 step 4, WP-6.07 /
// DEV-119): the operator reads behind GET /retention/runs and
// GET /retention/runs/{id}. They are gated on retention.manage (Administrator)
// like the rest of the retention surface, open no transaction and write no
// audit row — they only translate the persisted report rows (the operational
// record that survives the deletion, §13.4 step 5).

// ListRetentionRunsInput is the retention-report list read.
type ListRetentionRunsInput struct {
	Actor Actor
}

// GetRetentionRunInput is the single-run read.
type GetRetentionRunInput struct {
	RunID string
	Actor Actor
}

// ListRetentionRuns returns every stored retention run, newest cutoff first
// (ARCH-007 §2.2 step 4). It is gated on retention.manage but is a read: it
// opens no transaction and writes no audit row.
func (s *Service) ListRetentionRuns(ctx context.Context, in ListRetentionRunsInput) ([]RetentionRun, error) {
	const op = "list_retention_runs"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return nil, err
	}
	if _, err := signalActor(op, in.Actor); err != nil {
		return nil, err
	}
	if s.retention == nil {
		return nil, InfraError(op, errors.New("retention repository is not wired"))
	}
	return s.retention.ListRuns(ctx)
}

// GetRetentionRun returns one retention run by its id (ARCH-007 §2.2 step 4):
// the counts-only dry-run report, the four-eyes approval and the final counts.
// An unknown id is a not-found error (the HTTP layer maps it to 404); a
// principal without retention.manage is denied with a ForbiddenError (403)
// before the row is returned.
func (s *Service) GetRetentionRun(ctx context.Context, in GetRetentionRunInput) (RetentionRun, error) {
	const op = "get_retention_run"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return RetentionRun{}, err
	}
	if _, err := signalActor(op, in.Actor); err != nil {
		return RetentionRun{}, err
	}
	if s.retention == nil {
		return RetentionRun{}, InfraError(op, errors.New("retention repository is not wired"))
	}
	if in.RunID == "" {
		return RetentionRun{}, Validationf(op, "run_id must not be empty")
	}
	return s.retention.GetRun(ctx, in.RunID)
}
