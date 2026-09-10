package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file extends the signal repository with the I4 guarded signal writes
// of ARCH-004 §2.1/§2.3 and §3 (WP-4.03 / DEV-073): the status transition,
// the manual priority override and its revert, the owner assignment and the
// P1 escalation marker, plus the plain by-id row read the command layer
// takes before a guarded write. Every mutating statement is guarded on the
// optimistic-lock version the client read: a stale version matches zero rows
// and surfaces as a conflict Error (HTTP 409, ch. 7.3), never a silent
// overwrite. The methods run on the caller's transaction (one command, one
// transaction, ch. 5.1) and return the stored row mapped back to the domain
// aggregate.

// GetRiskSignal returns the plain stored signal row (no joins) mapped to the
// domain aggregate — the read the I4 command layer takes before a guarded
// transition or override. A missing row is a not-found Error.
func (r *SignalRepo) GetRiskSignal(ctx context.Context, id string) (domain.RiskSignal, error) {
	const op = "signals.get_risk_signal"

	uid, err := toUUID(id)
	if err != nil {
		return domain.RiskSignal{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetRiskSignalByID(ctx, uid)
	if err != nil {
		return domain.RiskSignal{}, mapDBError(op, err)
	}
	return riskSignalFromRow(op, row)
}

// Transition applies the ch. 6.3 status change of ARCH-004 §2 under the
// optimistic lock: it writes the new status and the closed_at stamp (the
// entry instant of a closed state; nil clears it on a non-closed target or a
// reopen) and bumps version. The domain state machine (domain.Transition)
// rules which edges are legal; a stale expectedVersion matches zero rows and
// is a conflict Error. The updated signal is returned.
func (r *SignalRepo) Transition(ctx context.Context, tx application.Tx, id string, to domain.SignalStatus, closedAt *time.Time, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.transition"

	if !to.Valid() {
		return domain.RiskSignal{}, application.Validationf(op, "invalid target status %q", to)
	}
	uid, err := toUUID(id)
	if err != nil {
		return domain.RiskSignal{}, application.ValidationError(op, err)
	}
	ver, err := versionInt32(op, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	row, err := r.q.WithTx(tx).TransitionRiskSignal(ctx, gen.TransitionRiskSignalParams{
		Status:          string(to),
		ClosedAt:        toTSPtrPtr(closedAt),
		ID:              uid,
		ExpectedVersion: ver,
	})
	if err != nil {
		return domain.RiskSignal{}, guardedSignalError(op, id, err)
	}
	return riskSignalFromRow(op, row)
}

// OverridePriority is the manual re-prioritisation of ARCH-004 §3 (ADR-015
// mirror): it sets the effective priority, preserves the computed value in
// auto_priority and stamps the mandatory reason/actor/time — the four
// override columns are all-set together (the schema CHECK enforces the
// all-or-nothing invariant). The caller supplies the computed autoPriority it
// read; the optimistic lock rejects a stale write. The updated signal is
// returned.
func (r *SignalRepo) OverridePriority(ctx context.Context, tx application.Tx, id string, priority, autoPriority domain.Priority, reason, actorID string, at time.Time, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.override_priority"

	if !priority.Valid() || !autoPriority.Valid() {
		return domain.RiskSignal{}, application.Validationf(op, "invalid priority %q/%q", priority, autoPriority)
	}
	if reason == "" || actorID == "" {
		return domain.RiskSignal{}, application.Validationf(op, "override reason and actor_id are mandatory")
	}
	if at.IsZero() {
		return domain.RiskSignal{}, application.Validationf(op, "override instant must not be zero")
	}
	uid, err := toUUID(id)
	if err != nil {
		return domain.RiskSignal{}, application.ValidationError(op, err)
	}
	ver, err := versionInt32(op, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	row, err := r.q.WithTx(tx).OverrideRiskSignalPriority(ctx, gen.OverrideRiskSignalPriorityParams{
		Priority:        string(priority),
		AutoPriority:    pgtype.Text{String: string(autoPriority), Valid: true},
		OverrideReason:  pgtype.Text{String: reason, Valid: true},
		OverrideActorID: pgtype.Text{String: actorID, Valid: true},
		OverrideAt:      toTS(at),
		ID:              uid,
		ExpectedVersion: ver,
	})
	if err != nil {
		return domain.RiskSignal{}, guardedSignalError(op, id, err)
	}
	return riskSignalFromRow(op, row)
}

// RevertPriority restores the computed priority from auto_priority and clears
// the four override columns in one guarded write (ARCH-004 §3). Reverting a
// signal without an active override leaves the row's override columns NULL
// and matches — the domain guards the "has an override" precondition; a
// stale expectedVersion is a conflict Error. The updated signal is returned.
func (r *SignalRepo) RevertPriority(ctx context.Context, tx application.Tx, id string, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.revert_priority"

	uid, err := toUUID(id)
	if err != nil {
		return domain.RiskSignal{}, application.ValidationError(op, err)
	}
	ver, err := versionInt32(op, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	row, err := r.q.WithTx(tx).RevertRiskSignalPriority(ctx, gen.RevertRiskSignalPriorityParams{
		ID:              uid,
		ExpectedVersion: ver,
	})
	if err != nil {
		return domain.RiskSignal{}, guardedSignalError(op, id, err)
	}
	return riskSignalFromRow(op, row)
}

// AssignOwner assigns the (opaque, until I5a resolves users) owner principal
// under the optimistic lock (ARCH-004 §2.1); "" clears the owner. A stale
// expectedVersion is a conflict Error. The updated signal is returned.
func (r *SignalRepo) AssignOwner(ctx context.Context, tx application.Tx, id, owner string, expectedVersion int) (domain.RiskSignal, error) {
	const op = "signals.assign_owner"

	uid, err := toUUID(id)
	if err != nil {
		return domain.RiskSignal{}, application.ValidationError(op, err)
	}
	ver, err := versionInt32(op, expectedVersion)
	if err != nil {
		return domain.RiskSignal{}, err
	}
	row, err := r.q.WithTx(tx).AssignRiskSignalOwner(ctx, gen.AssignRiskSignalOwnerParams{
		Owner:           toTextOpt(owner),
		ID:              uid,
		ExpectedVersion: ver,
	})
	if err != nil {
		return domain.RiskSignal{}, guardedSignalError(op, id, err)
	}
	return riskSignalFromRow(op, row)
}

// RecomputePriority persists the outcome of a targeted priority recompute
// (ARCH-004 §5, ch. 9.5) on the caller's transaction: the freshly rebuilt
// factor set, the rule version the recompute ran under and the recomputed
// computed priority. The override-survival mirror of §3 (ADR-015) is
// enforced in the SQL SET list — a purely computed signal updates the
// effective priority, an overridden one updates auto_priority only and keeps
// the human decision. The statement is not version-guarded (the command's
// changed-only comparison keeps an identical recompute from reaching it) and
// bumps version. The updated row is returned.
func (r *SignalRepo) RecomputePriority(ctx context.Context, tx application.Tx, id string, priority domain.Priority, ruleVersion string, factors domain.PriorityFactors) (domain.RiskSignal, error) {
	const op = "signals.recompute_priority"

	if !priority.Valid() {
		return domain.RiskSignal{}, application.Validationf(op, "invalid priority %q", priority)
	}
	if ruleVersion == "" {
		return domain.RiskSignal{}, application.Validationf(op, "rule_version must not be empty")
	}
	factorsJSON, err := json.Marshal(factors)
	if err != nil {
		return domain.RiskSignal{}, application.InfraError(op, err)
	}
	uid, err := toUUID(id)
	if err != nil {
		return domain.RiskSignal{}, application.ValidationError(op, err)
	}
	row, err := r.q.WithTx(tx).RecomputeRiskSignalPriority(ctx, gen.RecomputeRiskSignalPriorityParams{
		Priority:    string(priority),
		RuleVersion: ruleVersion,
		Factors:     factorsJSON,
		ID:          uid,
	})
	if err != nil {
		return domain.RiskSignal{}, mapDBError(op, err)
	}
	return riskSignalFromRow(op, row)
}

// MarkEscalated records the first P1 escalation instant (ARCH-004 §4.4). The
// statement's escalated_at IS NULL guard makes it set-once: the first call
// stamps the row and returns true; every later call matches zero rows and
// returns false (already escalated — not an error). A missing signal is
// indistinguishable from an already-escalated one here (both match zero
// rows); the escalation caller reads the signal first.
func (r *SignalRepo) MarkEscalated(ctx context.Context, tx application.Tx, id string, at time.Time) (bool, error) {
	const op = "signals.mark_escalated"

	if at.IsZero() {
		return false, application.Validationf(op, "escalation instant must not be zero")
	}
	uid, err := toUUID(id)
	if err != nil {
		return false, application.ValidationError(op, err)
	}
	_, err = r.q.WithTx(tx).MarkRiskSignalEscalated(ctx, gen.MarkRiskSignalEscalatedParams{
		EscalatedAt: toTS(at),
		ID:          uid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, mapDBError(op, err)
	}
	return true, nil
}

// guardedSignalError maps a zero-row guarded write (pgx.ErrNoRows, a stale
// optimistic-lock version) onto a conflict Error and defers every other
// driver error to mapDBError. It is the shared classification of the I4
// signal writes (ARCH-004 §2.3: stale versions yield HTTP 409).
func guardedSignalError(op, id string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ConflictError(op, fmt.Errorf("signal %s: stale version (optimistic lock failed)", id))
	}
	return mapDBError(op, err)
}

// versionInt32 narrows an optimistic-lock version to the int32 range of the
// version column; a value the column cannot hold is a validation error.
func versionInt32(op string, v int) (int32, error) {
	if v < 0 || v > math.MaxInt32 {
		return 0, application.Validationf(op, "version %d outside the int32 range", v)
	}
	return int32(v), nil
}

// toTSPtrPtr maps an optional time onto a nullable timestamptz: nil is NULL.
func toTSPtrPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return toTS(*t)
}
