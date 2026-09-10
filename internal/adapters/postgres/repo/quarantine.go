package repo

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// QuarantineRepo is the postgres implementation of application.QuarantineRepo
// (quarantine.sql): the ch. 8.6 isolation state machine of ARCH-002 §3/§4 —
// the isolation insert (status 'new'), the working-list and by-id reads, and
// the guarded state transitions new -> acknowledged -> ready_for_retry ->
// resolved (reprocess failures increment attempts and stay retryable).
//
// Every transition statement is guarded on the source status (ARCH-002 §4),
// so a transition that does not apply matches zero rows. The repo reports
// that as a conflict — the state changed between the caller's read and this
// write — so the command layer never writes the audit event of a transition
// that did not happen (ch. 13.2: one command, one transaction).
type QuarantineRepo struct {
	q *gen.Queries
}

// NewQuarantineRepo binds the repository to one query set.
func NewQuarantineRepo(q *gen.Queries) *QuarantineRepo { return &QuarantineRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.QuarantineRepo = (*QuarantineRepo)(nil)

// Insert implements application.QuarantineRepo: isolate one failed record
// slice in status 'new' (attempts 0 — the column default) and return its
// id. sourceID, position, reason and payloadHash are required; sourceRunID
// and rawRecordID are optional ("" stores NULL — the isolation is not yet
// attributed to a run/raw record).
func (r *QuarantineRepo) Insert(ctx context.Context, tx application.Tx, sourceID, sourceRunID, rawRecordID, position, reason, payloadHash string, now time.Time) (string, error) {
	const op = "quarantine.insert"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	runID, err := optUUID(sourceRunID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	rawID, err := optUUID(rawRecordID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).InsertQuarantine(ctx, gen.InsertQuarantineParams{
		SourceID:    srcID,
		SourceRunID: runID,
		RawRecordID: rawID,
		Position:    position,
		Reason:      reason,
		PayloadHash: payloadHash,
		CreatedAt:   toTS(now),
		UpdatedAt:   toTS(now),
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(row.ID), nil
}

// GetByID implements application.QuarantineRepo: load one quarantined row by
// id. A missing row is a not-found Error.
func (r *QuarantineRepo) GetByID(ctx context.Context, id string) (domain.Quarantine, error) {
	const op = "quarantine.get_by_id"

	qid, err := toUUID(id)
	if err != nil {
		return domain.Quarantine{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetQuarantineByID(ctx, qid)
	if err != nil {
		return domain.Quarantine{}, mapDBError(op, err)
	}
	return toQuarantine(row), nil
}

// List implements application.QuarantineRepo: the working-list read, oldest
// isolation first (created_at then id), with optional status/source filters.
func (r *QuarantineRepo) List(ctx context.Context, status *domain.QuarantineStatus, sourceID string, limit int) ([]domain.Quarantine, error) {
	const op = "quarantine.list"

	if limit < 1 || int64(limit) > math.MaxInt32 {
		return nil, application.Validationf(op, "limit %d outside [1, %d]", limit, math.MaxInt32)
	}
	srcID, err := optUUID(sourceID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	statusText := pgtypeTextOf(status)
	rows, err := r.q.ListQuarantine(ctx, gen.ListQuarantineParams{
		Status:   statusText,
		SourceID: srcID,
		MaxRows:  int32(limit),
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]domain.Quarantine, 0, len(rows))
	for _, row := range rows {
		out = append(out, toQuarantine(row))
	}
	return out, nil
}

// Acknowledge implements application.QuarantineRepo: the operator review
// transition new -> acknowledged, guarded on status = 'new' in SQL.
func (r *QuarantineRepo) Acknowledge(ctx context.Context, tx application.Tx, id, acknowledgedBy, note string, now time.Time) (domain.Quarantine, error) {
	const op = "quarantine.acknowledge"

	qid, err := toUUID(id)
	if err != nil {
		return domain.Quarantine{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).AcknowledgeQuarantine(ctx, gen.AcknowledgeQuarantineParams{
		ID:               qid,
		AcknowledgedAt:   toTS(now),
		AcknowledgedBy:   toTextOpt(acknowledgedBy),
		AcknowledgedNote: toTextOpt(note),
		UpdatedAt:        toTS(now),
	})
	if err != nil {
		return domain.Quarantine{}, transitionErr(op, err)
	}
	return toQuarantine(row), nil
}

// MarkReadyForRetry implements application.QuarantineRepo: new /
// acknowledged -> ready_for_retry, guarded in SQL.
func (r *QuarantineRepo) MarkReadyForRetry(ctx context.Context, tx application.Tx, id string, now time.Time) (domain.Quarantine, error) {
	const op = "quarantine.ready_for_retry"

	qid, err := toUUID(id)
	if err != nil {
		return domain.Quarantine{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkQuarantineReadyForRetry(ctx, gen.MarkQuarantineReadyForRetryParams{
		ID:        qid,
		UpdatedAt: toTS(now),
	})
	if err != nil {
		return domain.Quarantine{}, transitionErr(op, err)
	}
	return toQuarantine(row), nil
}

// MarkResolved implements application.QuarantineRepo: the terminal transition
// of a successful reprocess (ready_for_retry or new -> resolved), guarded in
// SQL. resolvedVulnerabilityID/resolvedEvidenceID link the new domain
// object ("" for none); note documents the outcome.
func (r *QuarantineRepo) MarkResolved(ctx context.Context, tx application.Tx, id, resolvedVulnerabilityID, resolvedEvidenceID, note string, now time.Time) (domain.Quarantine, error) {
	const op = "quarantine.resolve"

	qid, err := toUUID(id)
	if err != nil {
		return domain.Quarantine{}, application.ValidationError(op, err)
	}
	vulnID, err := optUUID(resolvedVulnerabilityID)
	if err != nil {
		return domain.Quarantine{}, application.ValidationError(op, err)
	}
	evidID, err := optUUID(resolvedEvidenceID)
	if err != nil {
		return domain.Quarantine{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).MarkQuarantineResolved(ctx, gen.MarkQuarantineResolvedParams{
		ID:                      qid,
		ResolvedAt:              toTS(now),
		ResolvedVulnerabilityID: vulnID,
		ResolvedEvidenceID:      evidID,
		ResolvedNote:            toTextOpt(note),
		UpdatedAt:               toTS(now),
	})
	if err != nil {
		return domain.Quarantine{}, transitionErr(op, err)
	}
	return toQuarantine(row), nil
}

// IncrementAttempts implements application.QuarantineRepo: a failed
// reprocess — attempts + 1, the row stays retryable (new / ready_for_retry
// -> attempts + 1), guarded in SQL.
func (r *QuarantineRepo) IncrementAttempts(ctx context.Context, tx application.Tx, id string, now time.Time) (domain.Quarantine, error) {
	const op = "quarantine.increment_attempts"

	qid, err := toUUID(id)
	if err != nil {
		return domain.Quarantine{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).IncrementQuarantineAttempts(ctx, gen.IncrementQuarantineAttemptsParams{
		ID:        qid,
		UpdatedAt: toTS(now),
	})
	if err != nil {
		return domain.Quarantine{}, transitionErr(op, err)
	}
	return toQuarantine(row), nil
}

// transitionErr reports a guarded-transition failure. pgx.ErrNoRows means
// the transition does not apply to the row's current state (it moved between
// the caller's read and this write) — a conflict, never a not-found.
func transitionErr(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ConflictError(op, errors.New("quarantine transition does not apply to the row's current status (state changed concurrently)"))
	}
	return mapDBError(op, err)
}

// toQuarantine maps a generated quarantine row onto the domain aggregate
// (plain struct scan; timestamps stay at the persistence layer, package
// doc of the domain).
func toQuarantine(row gen.Quarantine) domain.Quarantine {
	return domain.Quarantine{
		ID:                      uuidString(row.ID),
		SourceID:                uuidString(row.SourceID),
		SourceRunID:             uuidString(row.SourceRunID),
		RawRecordID:             uuidString(row.RawRecordID),
		Position:                row.Position,
		Reason:                  row.Reason,
		PayloadHash:             row.PayloadHash,
		Status:                  domain.QuarantineStatus(row.Status),
		Attempts:                int(row.Attempts),
		AcknowledgedBy:          row.AcknowledgedBy.String,
		AcknowledgedNote:        row.AcknowledgedNote.String,
		ResolvedVulnerabilityID: uuidString(row.ResolvedVulnerabilityID),
		ResolvedEvidenceID:      uuidString(row.ResolvedEvidenceID),
		ResolvedNote:            row.ResolvedNote.String,
	}
}

// optUUID parses an optional canonical uuid string; "" maps onto the invalid
// pgtype.UUID that stores NULL.
func optUUID(s string) (pgtype.UUID, error) {
	if s == "" {
		return pgtype.UUID{}, nil
	}
	return toUUID(s)
}

// pgtypeTextOf maps an optional domain status onto the nullable text filter
// of ListQuarantine; nil keeps the filter open.
func pgtypeTextOf(status *domain.QuarantineStatus) pgtype.Text {
	if status == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: string(*status), Valid: true}
}
