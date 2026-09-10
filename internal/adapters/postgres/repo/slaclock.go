package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// SlaClockRepo is the postgres implementation of the I4 SLA clocks
// (sla_clocks.sql, ARCH-004 §4, WP-4.03 / DEV-073): the natural-key
// (signal_id, target) upsert, the fulfil/pause/resume guarded writes, the
// reopen reset and the due-deadline breach scan. The command layer (WP-4.04)
// and the worker (WP-4.05) supply the injected clock instants; this adapter
// only persists and maps the stored rows back to the domain value object.
type SlaClockRepo struct {
	q *gen.Queries
}

// NewSlaClockRepo binds the repository to one query set.
func NewSlaClockRepo(q *gen.Queries) *SlaClockRepo { return &SlaClockRepo{q: q} }

// Upsert writes one clock's full state by its natural key (signal_id,
// target): a fresh insert, or the full-state replacement of an existing
// clock. It is the create path and the reopen reset in one statement — a
// reopen caller passes the reset state (started_at = now, deadline_at =
// now + duration, zeroed fulfilment/pause fields). The stored row is
// returned.
func (r *SlaClockRepo) Upsert(ctx context.Context, tx application.Tx, clock domain.SlaClock) (domain.SlaClock, error) {
	const op = "sla_clocks.upsert"

	uid, err := toUUID(clock.SignalID)
	if err != nil {
		return domain.SlaClock{}, application.ValidationError(op, err)
	}
	if !clock.Target.Valid() {
		return domain.SlaClock{}, application.Validationf(op, "invalid SLA target %q", clock.Target)
	}
	if clock.StartedAt.IsZero() || clock.DeadlineAt.IsZero() {
		return domain.SlaClock{}, application.Validationf(op, "started_at and deadline_at are mandatory")
	}
	row, err := r.q.WithTx(tx).UpsertSlaClock(ctx, gen.UpsertSlaClockParams{
		SignalID:      uid,
		Target:        string(clock.Target),
		StartedAt:     toTS(clock.StartedAt),
		DeadlineAt:    toTS(clock.DeadlineAt),
		FulfilledAt:   toTSPtr(clock.FulfilledAt),
		PausedSeconds: clock.PausedSeconds,
		PausedAt:      toTSPtr(clock.PausedAt),
	})
	if err != nil {
		return domain.SlaClock{}, mapDBError(op, err)
	}
	return slaClockFromRow(row), nil
}

// Get returns one clock by its natural key (signal_id, target) and whether it
// exists — the read the priority-upgrade treatment takes before it decides
// whether a target's clock is missing (create it) or present (tighten it if
// the new deadline is earlier). A missing clock is (zero, false, nil), not an
// error. The read runs on the caller's transaction so it sees the snapshot the
// following write acts on.
func (r *SlaClockRepo) Get(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget) (domain.SlaClock, bool, error) {
	const op = "sla_clocks.get"

	uid, err := toUUID(signalID)
	if err != nil {
		return domain.SlaClock{}, false, application.ValidationError(op, err)
	}
	if !target.Valid() {
		return domain.SlaClock{}, false, application.Validationf(op, "invalid SLA target %q", target)
	}
	row, err := r.q.WithTx(tx).GetSlaClock(ctx, gen.GetSlaClockParams{
		SignalID: uid,
		Target:   string(target),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.SlaClock{}, false, nil
		}
		return domain.SlaClock{}, false, mapDBError(op, err)
	}
	return slaClockFromRow(row), true, nil
}

// Tighten shortens one open clock's deadline to deadlineAt (ARCH-004 §4.3),
// reporting whether it changed the clock. The statement's
// `deadline_at > $2 AND fulfilled_at IS NULL` guard is the whole rule: only a
// clock whose stored deadline is later than deadlineAt — and that is not
// fulfilled — matches, so an upgrade never lengthens a window and a re-run is
// idempotent. A missing, fulfilled or already-earlier clock matches zero rows
// and reports changed = false (not an error). The stored clock is returned
// when a row changed.
func (r *SlaClockRepo) Tighten(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, deadlineAt time.Time) (domain.SlaClock, bool, error) {
	const op = "sla_clocks.tighten"

	uid, err := toUUID(signalID)
	if err != nil {
		return domain.SlaClock{}, false, application.ValidationError(op, err)
	}
	if !target.Valid() {
		return domain.SlaClock{}, false, application.Validationf(op, "invalid SLA target %q", target)
	}
	if deadlineAt.IsZero() {
		return domain.SlaClock{}, false, application.Validationf(op, "deadline instant must not be zero")
	}
	row, err := r.q.WithTx(tx).TightenSlaClock(ctx, gen.TightenSlaClockParams{
		DeadlineAt: toTS(deadlineAt),
		SignalID:   uid,
		Target:     string(target),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.SlaClock{}, false, nil // missing / fulfilled / already at least as early
		}
		return domain.SlaClock{}, false, mapDBError(op, err)
	}
	return slaClockFromRow(row), true, nil
}

// Fulfil marks the target met at the instant (ARCH-004 §4.3), returning the
// stored clock and whether the fulfil changed it. The statement's
// fulfilled_at IS NULL guard makes it idempotent: an already-fulfilled clock
// matches zero rows and reports changed = false (a fulfilled clock is never
// re-opened); a clock that does not exist is indistinguishable from an
// already-fulfilled one here (both report changed = false).
func (r *SlaClockRepo) Fulfil(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, bool, error) {
	const op = "sla_clocks.fulfil"

	uid, err := toUUID(signalID)
	if err != nil {
		return domain.SlaClock{}, false, application.ValidationError(op, err)
	}
	if !target.Valid() {
		return domain.SlaClock{}, false, application.Validationf(op, "invalid SLA target %q", target)
	}
	if at.IsZero() {
		return domain.SlaClock{}, false, application.Validationf(op, "fulfil instant must not be zero")
	}
	row, err := r.q.WithTx(tx).FulfilSlaClock(ctx, gen.FulfilSlaClockParams{
		FulfilledAt: toTS(at),
		SignalID:    uid,
		Target:      string(target),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.SlaClock{}, false, nil
		}
		return domain.SlaClock{}, false, mapDBError(op, err)
	}
	return slaClockFromRow(row), true, nil
}

// Pause starts a pause at the instant (ARCH-004 §4.3): paused_at is set
// while the clock runs. A fulfilled or already-paused clock (or a missing
// one) matches zero rows and is a conflict — the domain guards the
// preconditions and the guard repeats them at the data layer. The stored
// clock is returned.
func (r *SlaClockRepo) Pause(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, error) {
	const op = "sla_clocks.pause"

	uid, err := toUUID(signalID)
	if err != nil {
		return domain.SlaClock{}, application.ValidationError(op, err)
	}
	if !target.Valid() {
		return domain.SlaClock{}, application.Validationf(op, "invalid SLA target %q", target)
	}
	if at.IsZero() {
		return domain.SlaClock{}, application.Validationf(op, "pause instant must not be zero")
	}
	row, err := r.q.WithTx(tx).PauseSlaClock(ctx, gen.PauseSlaClockParams{
		PausedAt: toTS(at),
		SignalID: uid,
		Target:   string(target),
	})
	if err != nil {
		return domain.SlaClock{}, guardedClockError(op, signalID, target, err)
	}
	return slaClockFromRow(row), nil
}

// Resume ends the active pause at the instant (ARCH-004 §4.3): the elapsed
// pause accumulates into paused_seconds and paused_at is cleared. A clock
// that is not paused (or missing) matches zero rows and is a conflict. The
// stored clock is returned.
func (r *SlaClockRepo) Resume(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, at time.Time) (domain.SlaClock, error) {
	const op = "sla_clocks.resume"

	uid, err := toUUID(signalID)
	if err != nil {
		return domain.SlaClock{}, application.ValidationError(op, err)
	}
	if !target.Valid() {
		return domain.SlaClock{}, application.Validationf(op, "invalid SLA target %q", target)
	}
	if at.IsZero() {
		return domain.SlaClock{}, application.Validationf(op, "resume instant must not be zero")
	}
	row, err := r.q.WithTx(tx).ResumeSlaClock(ctx, gen.ResumeSlaClockParams{
		ResumedAt: toTS(at),
		SignalID:  uid,
		Target:    string(target),
	})
	if err != nil {
		return domain.SlaClock{}, guardedClockError(op, signalID, target, err)
	}
	return slaClockFromRow(row), nil
}

// Reset restarts one clock on a reopen (ARCH-004 §4.3): started_at = now,
// deadline_at = now + duration, fulfilled_at cleared and the pause counters
// zeroed. The caller resets only the targets defined at the current
// priority. A clock that does not exist is a not-found error. The stored
// clock is returned.
func (r *SlaClockRepo) Reset(ctx context.Context, tx application.Tx, signalID string, target domain.SLATarget, startedAt, deadlineAt time.Time) (domain.SlaClock, error) {
	const op = "sla_clocks.reset"

	uid, err := toUUID(signalID)
	if err != nil {
		return domain.SlaClock{}, application.ValidationError(op, err)
	}
	if !target.Valid() {
		return domain.SlaClock{}, application.Validationf(op, "invalid SLA target %q", target)
	}
	if startedAt.IsZero() || deadlineAt.IsZero() {
		return domain.SlaClock{}, application.Validationf(op, "started_at and deadline_at are mandatory")
	}
	row, err := r.q.WithTx(tx).ResetSlaClock(ctx, gen.ResetSlaClockParams{
		StartedAt:  toTS(startedAt),
		DeadlineAt: toTS(deadlineAt),
		SignalID:   uid,
		Target:     string(target),
	})
	if err != nil {
		return domain.SlaClock{}, mapDBError(op, err) // ErrNoRows -> not-found
	}
	return slaClockFromRow(row), nil
}

// Due returns the open clocks whose effective deadline has passed at the
// database clock — the sla.evaluate breach scan (ARCH-004 §4.3/§4.4). The
// effective deadline accounts for accumulated and running pauses; the caller
// (worker) decides escalation per priority. No due clock yields an empty
// slice, never an error.
func (r *SlaClockRepo) Due(ctx context.Context) ([]domain.SlaClock, error) {
	const op = "sla_clocks.due"

	rows, err := r.q.ScanDueSlaClocks(ctx)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]domain.SlaClock, 0, len(rows))
	for _, row := range rows {
		out = append(out, slaClockFromRow(row))
	}
	return out, nil
}

// guardedClockError maps a zero-row guarded clock write (the precondition
// did not apply — already fulfilled / already paused / not paused / missing)
// onto a conflict Error, deferring every other driver error to mapDBError.
func guardedClockError(op, signalID string, target domain.SLATarget, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ConflictError(op, fmt.Errorf("sla clock %s/%s: guard did not match (already fulfilled/paused, not paused, or missing)", signalID, target))
	}
	return mapDBError(op, err)
}

// slaClockFromRow maps a stored sla_clocks row onto the domain clock value
// object (absent timestamps map to the zero time — the domain's "open"/"not
// paused" sentinels).
func slaClockFromRow(row gen.SlaClock) domain.SlaClock {
	return domain.SlaClock{
		ID:            uuidString(row.ID),
		SignalID:      uuidString(row.SignalID),
		Target:        domain.SLATarget(row.Target),
		StartedAt:     tsTime(row.StartedAt),
		DeadlineAt:    tsTime(row.DeadlineAt),
		FulfilledAt:   tsTime(row.FulfilledAt),
		PausedSeconds: row.PausedSeconds,
		PausedAt:      tsTime(row.PausedAt),
	}
}
