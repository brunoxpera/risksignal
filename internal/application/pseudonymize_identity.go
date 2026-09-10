package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the PseudonymizeIdentity use case (ARCH-007 §3, ADR-014,
// WP-6.05 / DEV-116): the standalone governed pseudonymisation behind
// `maintenance identity-pseudonymize` (concept ch. 11.3). It reduces the
// personal reference of one identity in place — it clears the actor display
// names of the identity's audit rows and redacts the free text the identity
// authored or triggered (comments, override reasons, the free-text "reason"
// key inside the before/after snapshots) — while keeping actor_id and the
// users row, so the identity stays resolvable through the governed
// audit.reveal_identity act. Pseudonymisation is reversible-by-resolution and
// explicitly not anonymisation.
//
// A pseudonymisation act has a mandatory dry-run (ch. 11.3): DryRun reports the
// per-target redaction counts without changing anything (no transaction, no
// audit row). The real run requires a documented reason and is audited
// (retention.pseudonymised) atomically — an unlogged pseudonymisation would be
// worse than none (ADR-014 point 4).

// RetentionRedactionMarker is the fixed marker the in-place redaction of a free
// text field writes (comments.body). It is a stable, non-personal value; the
// redacted content is not recoverable (ADR-014: free text is not reversible).
const RetentionRedactionMarker = "[redacted]"

// PseudonymizeIdentityInput is the standalone pseudonymisation command. DryRun
// reports the counts only; a real run requires a documented Reason.
type PseudonymizeIdentityInput struct {
	UserID        string
	DryRun        bool
	Reason        string
	Actor         Actor
	CorrelationID string
}

// PseudonymizeIdentityResult reports the act: the target identity, whether it
// was a dry run and the per-target redaction counts.
type PseudonymizeIdentityResult struct {
	UserID    string
	DryRun    bool
	Redaction RetentionRedaction
}

// PseudonymizeIdentity pseudonymises one identity in place (ARCH-007 §3). The
// flow:
//
//  1. Authorize retention.manage (Admin) — deny-by-default, before any read
//     or transaction.
//  2. Dry-run: return the per-target counts (a read), changing nothing and
//     writing no audit row.
//  3. Real run: validate the mandatory documented reason, then in one
//     transaction redact the identity in place and append the
//     retention.pseudonymised audit event — atomically.
func (s *Service) PseudonymizeIdentity(ctx context.Context, in PseudonymizeIdentityInput) (PseudonymizeIdentityResult, error) {
	const op = "pseudonymize_identity"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionRetentionManage, domain.ScopeAll, ""); err != nil {
		return PseudonymizeIdentityResult{}, err
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return PseudonymizeIdentityResult{}, err
	}
	if s.retention == nil {
		return PseudonymizeIdentityResult{}, InfraError(op, errors.New("retention repository is not wired"))
	}
	if in.UserID == "" {
		return PseudonymizeIdentityResult{}, Validationf(op, "user_id must not be empty")
	}

	// The mandatory dry-run: a read that changes nothing and writes no audit.
	if in.DryRun {
		redaction, err := s.retention.PreviewPseudonymiseIdentity(ctx, in.UserID)
		if err != nil {
			return PseudonymizeIdentityResult{}, err
		}
		return PseudonymizeIdentityResult{UserID: in.UserID, DryRun: true, Redaction: redaction}, nil
	}

	if strings.TrimSpace(in.Reason) == "" {
		return PseudonymizeIdentityResult{}, Validationf(op, "a reason is mandatory for a pseudonymisation")
	}

	now := s.clock.Now()
	correlationID := correlationOrNew(in.CorrelationID)
	var redaction RetentionRedaction
	err = s.runTx(ctx, func(tx Tx) error {
		counts, err := s.retention.PseudonymiseIdentity(ctx, tx, in.UserID)
		if err != nil {
			return err
		}
		redaction = counts
		after, err := json.Marshal(pseudonymiseSnapshot{
			UserID:                  in.UserID,
			DisplayNamesCleared:     counts.DisplayNamesCleared,
			CommentBodiesRedacted:   counts.CommentBodiesRedacted,
			OverrideReasonsRedacted: counts.OverrideReasonsRedacted,
			SnapshotReasonsRedacted: counts.SnapshotReasonsRedacted,
			Reason:                  in.Reason,
		})
		if err != nil {
			return InfraError(op, err)
		}
		return s.appendRetentionAudit(ctx, tx, EventTypeRetentionPseudonymised, AuditAggregateUser, in.UserID, actor, correlationID, now, after)
	})
	if err != nil {
		return PseudonymizeIdentityResult{}, err
	}
	return PseudonymizeIdentityResult{UserID: in.UserID, DryRun: false, Redaction: redaction}, nil
}
