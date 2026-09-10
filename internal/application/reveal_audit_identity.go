package application

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the governed audit.reveal_identity act of ARCH-005 §7
// (WP-5a.07 / DEV-094, ADR-014): the RevealAuditIdentity use case that
// resolves an audit event's user actor against the internal users table and
// self-audits the resolution.
//
// It is a fachlicher Akt, never a list-view side-effect (ADR-014 point 4):
// the caller must hold audit.reveal_identity (Auditor / Product Owner only,
// never Administrator), supply a mandatory non-blank reason, and the
// resolution writes its own audit.identity_revealed event — atomically, in
// the same transaction, before anything is returned. An unlogged resolution
// would be worse than none ("in full or not at all", ADR-014).

// Audit action of the self-audit the reveal writes (ARCH-005 §7 step 5,
// ADR-014 point 4, concept ch. 13.2).
const (
	// EventTypeAuditIdentityRevealed is the audit action of the self-audit
	// emitted by every successful user-identity reveal.
	EventTypeAuditIdentityRevealed = "audit.identity_revealed"
	// AuditAggregateAuditEvent is the aggregate type of the reveal self-audit:
	// the revealed audit event is the aggregate the row describes.
	AuditAggregateAuditEvent = "audit_event"
)

// RevealAuditIdentityInput is the RevealAuditIdentity command (ARCH-005 §7):
// resolve the user actor of one audit event. Reason is mandatory and
// non-blank; Actor is the authenticated principal performing the reveal (its
// audit.reveal_identity gate is checked before any read or write).
type RevealAuditIdentityInput struct {
	// EventID is the audit event whose actor is revealed (audit_events.id).
	EventID string
	// Reason is the mandatory justification, recorded in the self-audit.
	Reason string
	// Actor is the revealing principal (a user principal in the API/CLI).
	Actor Actor
	// CorrelationID links the self-audit row to its command. Empty generates
	// one.
	CorrelationID string
}

// RevealAuditIdentityResult is the outcome of a reveal. Exactly one shape
// applies: for a user actor the resolved identity (UserID/SubjectID/
// DisplayName) is set and IsUser is true; for a system/service actor there
// is no identity to resolve and Label carries the actor's own label
// (ActorID, e.g. "sla.evaluate"), with IsUser false.
type RevealAuditIdentityResult struct {
	// EventID is the revealed audit event's id.
	EventID string
	// EventActorType is the target event's actor_type ("user", "system" or
	// "service").
	EventActorType string
	// IsUser reports whether the target actor was a user and an identity was
	// resolved.
	IsUser bool
	// Label is the display label: the resolved user's display name (or the
	// "User #<short-id>" fallback of a pseudonymised row) for a user actor,
	// or the system/service actor's own label otherwise.
	Label string
	// UserID is the resolved internal users.id ("" for a non-user actor).
	UserID string
	// SubjectID is the resolved issuer-qualified external subject ("" for a
	// non-user actor).
	SubjectID string
	// DisplayName is the resolved user's display name ("" when pseudonymised
	// or for a non-user actor). Label carries the rendered fallback.
	DisplayName string
}

// revealSnapshot is the minimised `after` snapshot of the self-audit
// (concept ch. 13.5: minimised state, no secrets): the revealed event, the
// resolved internal target and the mandatory reason. The subject id is
// deliberately not duplicated here — the target users.id is the stable
// reference and the identity is resolved on demand.
type revealSnapshot struct {
	EventID      string `json:"event_id"`
	TargetUserID string `json:"target_user_id"`
	Reason       string `json:"reason"`
}

// RevealAuditIdentity resolves the user actor of one audit event and records
// the resolution (ARCH-005 §7). The flow:
//
//  1. Authorize audit.reveal_identity (deny ⇒ nothing written, no read);
//  2. validate a mandatory, non-blank reason (blank ⇒ validation error, no
//     reveal);
//  3. load the audit event; a non-user actor returns its system/service label
//     (nothing to resolve, nothing written);
//  4. resolve actor_id → users by internal id (a deactivated user still
//     resolves — the deactivated record is the key, ADR-014 §3);
//  5. append the self-audit audit.identity_revealed atomically, in the same
//     transaction — a failing append rolls the whole reveal back and nothing
//     is returned;
//  6. return the resolved identity.
func (s *Service) RevealAuditIdentity(ctx context.Context, in RevealAuditIdentityInput) (RevealAuditIdentityResult, error) {
	const op = "reveal_audit_identity"

	// 1) The permission gate is the first step: a denial opens no transaction
	// and writes nothing (deny-by-default, ARCH-005 §5). audit.reveal_identity
	// is unconditional (all scope) — no object owner bounds it.
	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionAuditRevealIdentity, domain.ScopeAll, ""); err != nil {
		return RevealAuditIdentityResult{}, err
	}
	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return RevealAuditIdentityResult{}, err
	}
	// 2) The reason is mandatory and non-blank.
	if strings.TrimSpace(in.Reason) == "" {
		return RevealAuditIdentityResult{}, Validationf(op, "a reason is mandatory")
	}
	if in.EventID == "" {
		return RevealAuditIdentityResult{}, Validationf(op, "event_id must not be empty")
	}
	if s.users == nil {
		return RevealAuditIdentityResult{}, InfraError(op, errUsersNotWired)
	}

	// 3) Load the event whose actor is to be resolved.
	ev, err := s.audit.GetEventByID(ctx, in.EventID)
	if err != nil {
		return RevealAuditIdentityResult{}, err
	}

	// A non-user actor has no identity to resolve: return its own label and
	// write nothing (there is no resolution to audit).
	if ev.ActorType != ActorTypeUser {
		return RevealAuditIdentityResult{
			EventID:        in.EventID,
			EventActorType: ev.ActorType,
			IsUser:         false,
			Label:          nonUserActorLabel(ev),
		}, nil
	}

	// 4) Resolve actor_id → users. A deactivated user still resolves.
	user, err := s.users.GetUserByID(ctx, ev.ActorID)
	if err != nil {
		return RevealAuditIdentityResult{}, err
	}
	label := identityLabel(user.DisplayName, user.ID)

	// 5) Self-audit the resolution atomically, in one transaction, before
	// returning: a failing append rolls the whole reveal back and nothing is
	// returned (ADR-014 "in full or not at all").
	correlationID := correlationOrNew(in.CorrelationID)
	var result RevealAuditIdentityResult
	err = s.runTx(ctx, func(tx Tx) error {
		now := s.clock.Now()
		after, err := json.Marshal(revealSnapshot{
			EventID:      in.EventID,
			TargetUserID: user.ID,
			Reason:       in.Reason,
		})
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.audit.Append(ctx, tx, AuditEvent{
			AggregateType:    AuditAggregateAuditEvent,
			AggregateID:      in.EventID,
			ActorType:        actor.Type,
			ActorID:          actor.ID,
			ActorDisplayName: actor.DisplayName,
			Action:           EventTypeAuditIdentityRevealed,
			OccurredAt:       now,
			Before:           nil,
			After:            after,
			CorrelationID:    correlationID,
		}); err != nil {
			return err
		}
		result = RevealAuditIdentityResult{
			EventID:        in.EventID,
			EventActorType: ActorTypeUser,
			IsUser:         true,
			Label:          label,
			UserID:         user.ID,
			SubjectID:      user.SubjectID,
			DisplayName:    user.DisplayName,
		}
		return nil
	})
	if err != nil {
		return RevealAuditIdentityResult{}, err
	}
	return result, nil
}

// nonUserActorLabel is the label of a system/service actor — its free-string
// actor id (e.g. "sla.evaluate", "demo-seed"), falling back to the recorded
// display name when the id is empty and finally to the actor type.
func nonUserActorLabel(ev AuditEvent) string {
	if ev.ActorID != "" {
		return ev.ActorID
	}
	if ev.ActorDisplayName != "" {
		return ev.ActorDisplayName
	}
	return ev.ActorType
}

// identityLabel renders the display label of a resolved user (ADR-014 §2):
// the display name when present, otherwise the "User #<short-id>" fallback
// of a row whose display name the pseudonymisation stage cleared.
func identityLabel(displayName, userID string) string {
	if strings.TrimSpace(displayName) != "" {
		return displayName
	}
	return "User #" + shortID(userID)
}

// shortID is the short form of a uuid used by the pseudonymised label
// ("User #<short-id>"): the hex before the first dash.
func shortID(id string) string {
	if i := strings.IndexByte(id, '-'); i > 0 {
		return id[:i]
	}
	return id
}

// ResolveActor maps an authenticated identity onto the audit Actor of a
// command (ARCH-005 §2/§6): the internal users.id is looked up by the
// issuer-qualified subject_id. The authenticated adapters (the reveal
// endpoint, the CLI identity-lookup) use it to turn a verified Identity into
// the user actor the authoriser and the audit rows key on. An unknown
// subject denies (fail closed — an authenticated identity with no internal
// user holds nothing); a deactivated user still resolves here (the use case's
// own gate decides its rights).
func (s *Service) ResolveActor(ctx context.Context, id domain.Identity) (Actor, error) {
	const op = "resolve_actor"

	if strings.TrimSpace(id.SubjectID) == "" {
		return Actor{}, Forbiddenf(op, "identity has no subject")
	}
	if s.users == nil {
		return Actor{}, InfraError(op, errUsersNotWired)
	}
	u, err := s.users.GetUserBySubject(ctx, id.SubjectID)
	if err != nil {
		if kind, _ := ErrorKindOf(err); kind == KindNotFound {
			return Actor{}, Forbiddenf(op, "unknown subject %q", id.SubjectID)
		}
		return Actor{}, InfraError(op, err)
	}
	display := u.DisplayName
	if display == "" {
		display = id.DisplayName
	}
	return Actor{Type: ActorTypeUser, ID: u.ID, DisplayName: display}, nil
}

// errUsersNotWired is the programming error of a gated use case invoked
// without the identity read port.
var errUsersNotWired = errors.New("application: user repository is not wired")
