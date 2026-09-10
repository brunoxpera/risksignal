// `risksignal maintenance identity-lookup` (concept ch. 11.3, ARCH-005 §7,
// WP-5a.07 / DEV-094, ADR-014): the CLI form of the governed
// audit.reveal_identity act. It drives the same use case as the API endpoint
//
//	POST /api/v1/audit-events/{id}/reveal-actor
//
// with the same permission gate and the same self-audit — the application
// layer is the gate of record, so no channel bypasses it (ARCH-005 §5,
// NFR-013 channel parity).
//
// The command is strictly non-interactive (ch. 11.3): the event id and the
// mandatory reason are complete command-line parameters, never a terminal
// dialogue. The acting identity is selected with --as (an issuer-qualified
// subject, e.g. "local::auditor"); it defaults to the configured
// auth.bypass_principal in the local namespace — the local development
// subject a verified token would carry. In production the subject comes from
// the CLI's OIDC login (I5b); --as only names which seeded/dev identity acts.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// identityLookupTimeout bounds one identity-lookup run; the reveal is a
// single read + one audit write, so the bound only protects automation from a
// hanging database.
const identityLookupTimeout = 30 * time.Second

// cmdIdentityLookup runs `risksignal maintenance identity-lookup --event <id>
// --reason <text> [--as <subject>]`: the governed reveal.
func (e *cmdEnv) cmdIdentityLookup(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal maintenance identity-lookup --event <audit-event-id> --reason <text> [--as <subject>]\n"+
		"  --event   audit event id whose user actor is revealed (mandatory)\n"+
		"  --reason  mandatory, non-blank justification (ADR-014)\n"+
		"  --as      acting identity's issuer-qualified subject\n"+
		"            (default: local::<auth.bypass_principal>)")
	event := fs.String("event", "", "audit event id whose user actor is revealed")
	reason := fs.String("reason", "", "mandatory, non-blank justification")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*event) == "" {
		return e.fail(exitValidation, classValidation, "--event is mandatory (the audit event id to reveal)")
	}
	if strings.TrimSpace(*reason) == "" {
		return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank (ADR-014)")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	subject := strings.TrimSpace(*as)
	if subject == "" {
		principal := strings.TrimSpace(cfg.Auth.BypassPrincipal)
		if principal == "" {
			principal = "local-developer"
		}
		subject = "local::" + principal
	}

	ctx, cancel := context.WithTimeout(context.Background(), identityLookupTimeout)
	defer cancel()

	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, err := svc.ResolveActor(ctx, domain.Identity{SubjectID: subject})
	if err != nil {
		return identityLookupErrorOutcome(err)
	}
	res, err := svc.RevealAuditIdentity(ctx, application.RevealAuditIdentityInput{
		EventID: *event,
		Reason:  *reason,
		Actor:   actor,
	})
	if err != nil {
		return identityLookupErrorOutcome(err)
	}

	payload := identityLookupResult{
		EventID:     res.EventID,
		ActorType:   res.EventActorType,
		IsUser:      res.IsUser,
		Label:       res.Label,
		UserID:      res.UserID,
		SubjectID:   res.SubjectID,
		DisplayName: res.DisplayName,
	}
	if e.format == formatText {
		printIdentityLookup(e.stdout, payload)
	}
	return e.ok(payload)
}

// identityLookupResult is the machine-readable payload of a successful
// identity lookup (schema-stable keys).
type identityLookupResult struct {
	EventID     string `json:"event_id"`
	ActorType   string `json:"actor_type"`
	IsUser      bool   `json:"is_user"`
	Label       string `json:"label"`
	UserID      string `json:"user_id,omitempty"`
	SubjectID   string `json:"subject_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// printIdentityLookup renders the outcome as human-readable text.
func printIdentityLookup(w io.Writer, r identityLookupResult) {
	if r.IsUser {
		fmt.Fprintf(w, "audit event %s: resolved user identity %q (user %s, subject %s)\n",
			r.EventID, r.Label, r.UserID, r.SubjectID)
		return
	}
	fmt.Fprintf(w, "audit event %s: actor is not a user (type %s, label %q) — no identity to reveal\n",
		r.EventID, r.ActorType, r.Label)
}

// identityLookupErrorOutcome maps the reveal use-case error classes onto the
// CLI exit-code contract (ch. 11.3): a validation mistake is exit 2, a denied
// permission exit 4 (authorisation), infrastructure trouble exit 6 and any
// other (unknown event, unexpected) the generic exit 1.
func identityLookupErrorOutcome(err error) outcome {
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindValidation:
		return outcome{code: exitValidation, class: classValidation, message: err.Error()}
	case application.KindForbidden:
		return outcome{code: exitAuthorisation, class: classAuthorisation, message: err.Error()}
	case application.KindInfra:
		return outcome{code: exitInfrastructure, class: classInfrastructure, message: err.Error()}
	default: // KindNotFound and anything unknown
		return outcome{code: exitGeneric, class: classGeneric, message: err.Error()}
	}
}
