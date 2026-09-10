package application

import (
	"context"
	"errors"
)

// This file owns the SweepExports use case (ARCH-007 §1.2, WP-6.04/6.06 /
// DEV-118): the daily export expiry sweep the worker drives. It lists the
// completed exports whose TTL elapsed, deletes their spool artifacts and marks
// the rows 'expired' — the terminal state of the export lifecycle. The
// retention/audit rows are never touched: an export is a time-limited
// business-content copy, not an audit record, and the sweep only reclaims the
// spool. It is idempotent (an already-sweped/expired row is no longer
// completed, so a second sweep matches nothing) and tolerant of an already
// deleted artifact (the row is still marked expired).

// SweepExportsResult reports one sweep run: the number of exports expired.
type SweepExportsResult struct {
	// Expired is the number of completed exports whose artifact was deleted
	// and whose row was flipped to 'expired'.
	Expired int
}

// SweepExports deletes the expired export artifacts and marks their rows
// 'expired' (ARCH-007 §1.2). The expiry is evaluated against the injected
// clock (NFR-015), never the wall clock: the cut is `expires_at <= now`. A
// missing artifact is not an error — the row is still marked expired, so a
// crash between the deletion and the mark cannot strand a row.
func (s *Service) SweepExports(ctx context.Context) (SweepExportsResult, error) {
	const op = "sweep_exports"

	if s.exports == nil {
		return SweepExportsResult{}, InfraError(op, errors.New("export repository is not wired"))
	}
	if s.exportStore == nil {
		return SweepExportsResult{}, InfraError(op, errors.New("export artifact store is not wired"))
	}

	now := s.clock.Now()
	expired, err := s.exports.ListExpired(ctx, now)
	if err != nil {
		return SweepExportsResult{}, err
	}

	swept := 0
	for _, row := range expired {
		if row.StoragePath != "" {
			// Remove is best-effort and idempotent: an already deleted (or
			// never materialised) artifact must not stop the sweep from
			// marking the row expired, or the row would leak 'completed'
			// forever.
			_ = s.exportStore.Remove(ctx, row.StoragePath)
		}
		err := s.runTx(ctx, func(tx Tx) error {
			_, err := s.exports.MarkExpired(ctx, tx, row.ID)
			return err
		})
		if err != nil {
			return SweepExportsResult{}, err
		}
		swept++
	}
	return SweepExportsResult{Expired: swept}, nil
}
