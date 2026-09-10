// `risksignal signal ...` (concept ch. 11.3, ARCH-005 §8, ARCH-006 §1/§5,
// WP-5a.08 / WP-5b.08): the CLI form of the I5b signal command surface. It
// drives the same application use cases as the API endpoint
//
//	POST /api/v1/signals/{signal_id}/commands
//
// with the same in-command permission gates and the same audit — the
// application layer is the gate of record, so no channel bypasses it
// (ARCH-005 §5, NFR-013 channel parity). The command vocabulary is 1:1 with
// the API (ARCH-006 §5):
//
//	risksignal signal list                              signals.read working list
//	risksignal signal show   --signal <id>              signals.read detail
//	risksignal signal acknowledge --signal <id> --version <n>        acknowledge
//	risksignal signal assign      --signal <id> --owner <id>|--clear --version <n>   assign_owner
//	risksignal signal transition  --signal <id> --to <status> [--reason <t>] --version <n>  change_status
//	risksignal signal comment     --signal <id> --comment <text>     add_comment
//	risksignal signal override    --signal <id> --priority <P1..P4> --reason <text> --version <n>  override_priority
//	risksignal signal revert      --signal <id> --version <n>        revert_priority
//	risksignal signal pause       --signal <id> --target <t> --reason <text>   pause_sla
//	risksignal signal resume      --signal <id> --target <t> --reason <text>   resume_sla
//
// Every command is strictly non-interactive (ch. 11.3): the signal id, the
// command and its parameters are complete command-line arguments, never a
// terminal dialogue. The acting identity is selected with --as (an
// issuer-qualified subject, e.g. "local::security-analyst"); it defaults to
// the configured auth.bypass_principal in the local namespace. In production
// the subject comes from the CLI's OIDC login (auth.go); --as only names
// which seeded/dev identity acts.

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
	"github.com/brunoxpera/risksignal/internal/platform/config"
)

// signalCommandTimeout bounds one command run; the command is a single read +
// one guarded write, so the bound only protects automation from a hanging
// database.
const signalCommandTimeout = 30 * time.Second

// The API command vocabulary the CLI mirrors (ARCH-006 §1.1/§5). The string
// values are the API enum values and the wire `command` of the result
// envelope.
const (
	signalCmdList             = "list"
	signalCmdShow             = "show"
	signalCmdAcknowledge      = "acknowledge"
	signalCmdChangeStatus     = "change_status"
	signalCmdAssignOwner      = "assign_owner"
	signalCmdAddComment       = "add_comment"
	signalCmdOverridePriority = "override_priority"
	signalCmdRevertPriority   = "revert_priority"
	signalCmdPauseSLA         = "pause_sla"
	signalCmdResumeSLA        = "resume_sla"
)

// signalSubcommands lists the supported subcommands for the error message.
const signalSubcommands = "list, show, acknowledge, assign, transition, comment, override, revert, pause, resume"

// runSignal dispatches `risksignal signal <subcommand>`.
func runSignal(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.emit("signal", e.fail(exitValidation, classValidation, "missing subcommand (supported: %s)", signalSubcommands))
	}
	command := "signal " + args[0]
	switch args[0] {
	case signalCmdList:
		return e.emit(command, e.cmdSignalList(args[1:]))
	case signalCmdShow:
		return e.emit(command, e.cmdSignalShow(args[1:]))
	case "acknowledge":
		return e.emit(command, e.cmdSignalAcknowledge(args[1:]))
	case "assign":
		return e.emit(command, e.cmdSignalAssign(args[1:]))
	case "transition":
		return e.emit(command, e.cmdSignalTransition(args[1:]))
	case "comment":
		return e.emit(command, e.cmdSignalComment(args[1:]))
	case "override":
		return e.emit(command, e.cmdSignalOverride(args[1:]))
	case "revert":
		return e.emit(command, e.cmdSignalRevert(args[1:]))
	case "pause":
		return e.emit(command, e.cmdSignalPause(args[1:]))
	case "resume":
		return e.emit(command, e.cmdSignalResume(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation, "unknown subcommand (supported: %s)", signalSubcommands))
	}
}

// cmdSignalAcknowledge runs `risksignal signal acknowledge --signal <id>
// --version <n> [--as <subject>]` (the API acknowledge command).
func (e *cmdEnv) cmdSignalAcknowledge(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal acknowledge --signal <id> --version <n> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to acknowledge (mandatory)")
	version := fs.Int("version", 0, "optimistic-lock version (mandatory, >= 1)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdAcknowledge,
		signal:  *signal,
		version: *version,
		as:      *as,
	})
}

// cmdSignalTransition runs `risksignal signal transition --signal <id>
// --to <status> [--reason <text>] --version <n> [--as <subject>]` (the API
// change_status command; the reason is mandatory on the closed-entry and
// reopen edges, enforced by the use case/domain).
func (e *cmdEnv) cmdSignalTransition(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal transition --signal <id> --to <status> [--reason <text>] --version <n> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to transition (mandatory)")
	to := fs.String("to", "", "target status: new, in_review, action_planned, resolved, accepted, not_affected (mandatory)")
	reason := fs.String("reason", "", "justification (mandatory on the closed-entry/reopen edges)")
	version := fs.Int("version", 0, "optimistic-lock version (mandatory, >= 1)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdChangeStatus,
		signal:  *signal,
		status:  *to,
		reason:  *reason,
		version: *version,
		as:      *as,
	})
}

// cmdSignalAssign runs `risksignal signal assign --signal <id>
// (--owner <id>|--clear) --version <n> [--as <subject>]` (the API
// assign_owner command; --clear clears the assignment).
func (e *cmdEnv) cmdSignalAssign(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal assign --signal <id> (--owner <id>|--clear) --version <n> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to assign (mandatory)")
	owner := fs.String("owner", "", "owner principal id; exactly one of --owner/--clear is mandatory")
	clear := fs.Bool("clear", false, "clear the owner assignment")
	version := fs.Int("version", 0, "optimistic-lock version (mandatory, >= 1)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	ownerSet := strings.TrimSpace(*owner) != ""
	if ownerSet == *clear {
		return e.fail(exitValidation, classValidation, "exactly one of --owner or --clear is mandatory")
	}
	value := *owner
	if *clear {
		value = ""
	}
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdAssignOwner,
		signal:  *signal,
		owner:   value,
		version: *version,
		as:      *as,
	})
}

// cmdSignalComment runs `risksignal signal comment --signal <id>
// --comment <text> [--as <subject>]` (the API add_comment command; it is
// append-only and not version-guarded).
func (e *cmdEnv) cmdSignalComment(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal comment --signal <id> --comment <text> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to comment on (mandatory)")
	comment := fs.String("comment", "", "comment body (mandatory)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdAddComment,
		signal:  *signal,
		comment: *comment,
		as:      *as,
	})
}

// cmdSignalOverride runs `risksignal signal override --signal <id>
// --priority <P1..P4> --reason <text> --version <n> [--as <subject>]` (the
// API override_priority command).
func (e *cmdEnv) cmdSignalOverride(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal override --signal <id> --priority <P1..P4> --reason <text> --version <n> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to override (mandatory)")
	priority := fs.String("priority", "", "new effective priority, P1..P4 (mandatory)")
	reason := fs.String("reason", "", "mandatory, non-blank justification")
	version := fs.Int("version", 0, "optimistic-lock version (mandatory, >= 1)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	return e.runSignalCommand(signalCommandArgs{
		command:  signalCmdOverridePriority,
		signal:   *signal,
		priority: *priority,
		reason:   *reason,
		version:  *version,
		as:       *as,
	})
}

// cmdSignalRevert runs `risksignal signal revert --signal <id> --version <n>
// [--as <subject>]` (the API revert_priority command).
func (e *cmdEnv) cmdSignalRevert(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal revert --signal <id> --version <n> [--as <subject>]")
	signal := fs.String("signal", "", "signal id whose override is reverted (mandatory)")
	version := fs.Int("version", 0, "optimistic-lock version (mandatory, >= 1)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdRevertPriority,
		signal:  *signal,
		version: *version,
		as:      *as,
	})
}

// cmdSignalPause runs `risksignal signal pause --signal <id> --target <t>
// --reason <text> [--as <subject>]` (the API pause_sla command; clock-state
// guarded, not version-guarded).
func (e *cmdEnv) cmdSignalPause(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal pause --signal <id> --target <notification|acknowledgement|assessment|decision> --reason <text> [--as <subject>]")
	signal := fs.String("signal", "", "signal id whose clock is paused (mandatory)")
	target := fs.String("target", "", "SLA target: notification, acknowledgement, assessment, decision (mandatory)")
	reason := fs.String("reason", "", "mandatory, non-blank justification")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdPauseSLA,
		signal:  *signal,
		target:  *target,
		reason:  *reason,
		as:      *as,
	})
}

// cmdSignalResume runs `risksignal signal resume --signal <id> --target <t>
// --reason <text> [--as <subject>]` (the API resume_sla command).
func (e *cmdEnv) cmdSignalResume(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal resume --signal <id> --target <notification|acknowledgement|assessment|decision> --reason <text> [--as <subject>]")
	signal := fs.String("signal", "", "signal id whose clock is resumed (mandatory)")
	target := fs.String("target", "", "SLA target: notification, acknowledgement, assessment, decision (mandatory)")
	reason := fs.String("reason", "", "mandatory, non-blank justification")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdResumeSLA,
		signal:  *signal,
		target:  *target,
		reason:  *reason,
		as:      *as,
	})
}

// cmdSignalList runs `risksignal signal list [--limit <n>] [--cursor <c>]
// [--priority <P1..P4>] [--status <status>] [--as <subject>]`: the
// cursor-paginated signals.read working list (ARCH-001 §4 listSignals).
func (e *cmdEnv) cmdSignalList(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal list [--limit <n>] [--cursor <c>] [--priority <P1..P4>] [--status <status>] [--as <subject>]")
	limit := fs.Int("limit", 0, "page size (default 20, max 100)")
	cursor := fs.String("cursor", "", "opaque page cursor from a previous page")
	priority := fs.String("priority", "", "priority filter: P1, P2, P3, P4")
	status := fs.String("status", "", "status filter: new, in_review, action_planned, resolved, accepted, not_affected")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if *limit < 0 {
		return e.fail(exitValidation, classValidation, "--limit must be >= 0")
	}
	in := application.ListSignalsInput{Limit: *limit, Cursor: *cursor}
	if v := strings.TrimSpace(*priority); v != "" {
		p := domain.Priority(v)
		if !p.Valid() {
			return e.fail(exitValidation, classValidation, "invalid priority filter %q (P1..P4)", v)
		}
		in.Priority = &p
	}
	if v := strings.TrimSpace(*status); v != "" {
		s := domain.SignalStatus(v)
		if !s.Valid() {
			return e.fail(exitValidation, classValidation, "invalid status filter %q", v)
		}
		in.Status = &s
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), signalCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveSignalActor(ctx, svc, cfg, *as)
	if !out.ok() {
		return out
	}
	in.Actor = actor
	page, err := svc.ListSignals(ctx, in)
	if err != nil {
		return applicationErrorOutcome(err)
	}
	result := signalListResult{Data: signalViews(page.Signals), NextCursor: page.NextCursor}
	if e.format == formatText {
		printSignalList(e.stdout, result)
	}
	return e.ok(result)
}

// cmdSignalShow runs `risksignal signal show --signal <id> [--as <subject>]`:
// the signals.read detail view (ARCH-001 §4 getSignal).
func (e *cmdEnv) cmdSignalShow(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal show --signal <id> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to show (mandatory)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*signal) == "" {
		return e.fail(exitValidation, classValidation, "--signal is mandatory (the signal id)")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), signalCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveSignalActor(ctx, svc, cfg, *as)
	if !out.ok() {
		return out
	}
	sig, err := svc.GetSignal(ctx, application.GetSignalInput{SignalID: *signal, Actor: actor})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	view := signalViewOf(sig)
	if e.format == formatText {
		printSignalShow(e.stdout, view)
	}
	return e.ok(view)
}

// signalCommandArgs carries the validated-on-entry arguments of one command
// run.
type signalCommandArgs struct {
	command  string
	signal   string
	status   string
	priority string
	owner    string
	comment  string
	reason   string
	target   string
	version  int
	as       string
}

// runSignalCommand resolves the acting identity and drives the matching
// application use case, mapping its error classes onto the CLI exit-code
// contract. It validates the command's mandatory flags before any database
// work (the same fields the API's per-command if/then declares).
func (e *cmdEnv) runSignalCommand(a signalCommandArgs) outcome {
	if strings.TrimSpace(a.signal) == "" {
		return e.fail(exitValidation, classValidation, "--signal is mandatory (the signal id)")
	}
	// The version-guarded commands require --version; the append-only comment
	// and the clock-state-guarded pause/resume do not (ARCH-006 §1.1).
	switch a.command {
	case signalCmdAcknowledge, signalCmdChangeStatus, signalCmdAssignOwner,
		signalCmdOverridePriority, signalCmdRevertPriority:
		if a.version < 1 {
			return e.fail(exitValidation, classValidation, "--version is mandatory and must be >= 1")
		}
	}
	switch a.command {
	case signalCmdChangeStatus:
		if strings.TrimSpace(a.status) == "" {
			return e.fail(exitValidation, classValidation, "--to is mandatory for transition")
		}
	case signalCmdOverridePriority:
		if strings.TrimSpace(a.priority) == "" {
			return e.fail(exitValidation, classValidation, "--priority is mandatory for override")
		}
		if strings.TrimSpace(a.reason) == "" {
			return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank for override")
		}
	case signalCmdAddComment:
		if strings.TrimSpace(a.comment) == "" {
			return e.fail(exitValidation, classValidation, "--comment is mandatory for comment")
		}
	case signalCmdPauseSLA, signalCmdResumeSLA:
		if strings.TrimSpace(a.target) == "" {
			return e.fail(exitValidation, classValidation, "--target is mandatory for pause/resume")
		}
		if strings.TrimSpace(a.reason) == "" {
			return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank for pause/resume")
		}
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), signalCommandTimeout)
	defer cancel()
	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, out := e.resolveSignalActor(ctx, svc, cfg, a.as)
	if !out.ok() {
		return out
	}

	result, err := e.dispatchSignalCommand(ctx, svc, a, actor)
	if err != nil {
		return applicationErrorOutcome(err)
	}
	if e.format == formatText {
		printSignalCommand(e.stdout, result)
	}
	return e.ok(result)
}

// dispatchSignalCommand maps one validated CLI command onto its application
// use case and builds the wire result. The signal-returning commands render
// their aggregate directly; the three commands whose use case returns a
// non-signal aggregate (add_comment, pause_sla, resume_sla) read the signal's
// post-command state back through GetSignal, exactly like the HTTP handler —
// never inventing a version.
func (e *cmdEnv) dispatchSignalCommand(ctx context.Context, svc *application.Service, a signalCommandArgs, actor application.Actor) (signalCommandResult, error) {
	switch a.command {
	case signalCmdAcknowledge:
		sig, err := svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
			SignalID: a.signal, ExpectedVersion: a.version, Actor: actor,
		})
		if err != nil {
			return signalCommandResult{}, err
		}
		return signalCommandResultOf(a.command, sig, nil, nil, nil), nil

	case signalCmdChangeStatus:
		sig, err := svc.TransitionSignal(ctx, application.TransitionSignalInput{
			SignalID: a.signal, To: domain.SignalStatus(a.status), Reason: a.reason,
			ExpectedVersion: a.version, Actor: actor,
		})
		if err != nil {
			return signalCommandResult{}, err
		}
		return signalCommandResultOf(a.command, sig, nil, nil, nil), nil

	case signalCmdAssignOwner:
		sig, err := svc.AssignOwner(ctx, application.AssignOwnerInput{
			SignalID: a.signal, Owner: a.owner, ExpectedVersion: a.version, Actor: actor,
		})
		if err != nil {
			return signalCommandResult{}, err
		}
		var owner *string
		if sig.Owner != "" {
			owner = &sig.Owner
		}
		return signalCommandResultOf(a.command, sig, owner, nil, nil), nil

	case signalCmdAddComment:
		if _, err := svc.AddComment(ctx, application.AddCommentInput{
			SignalID: a.signal, Body: a.comment, Actor: actor,
		}); err != nil {
			return signalCommandResult{}, err
		}
		return e.postCommandResult(ctx, svc, a.command, a.signal, actor)

	case signalCmdOverridePriority:
		sig, err := svc.OverridePriority(ctx, application.OverridePriorityInput{
			SignalID: a.signal, Priority: domain.Priority(a.priority), Reason: a.reason,
			ExpectedVersion: a.version, Actor: actor,
		})
		if err != nil {
			return signalCommandResult{}, err
		}
		return signalCommandResultOf(a.command, sig, nil, nil, sig.AutoPriority), nil

	case signalCmdRevertPriority:
		sig, err := svc.RevertPriority(ctx, application.RevertPriorityInput{
			SignalID: a.signal, ExpectedVersion: a.version, Actor: actor,
		})
		if err != nil {
			return signalCommandResult{}, err
		}
		return signalCommandResultOf(a.command, sig, nil, nil, sig.AutoPriority), nil

	case signalCmdPauseSLA, signalCmdResumeSLA:
		target := domain.SLATarget(a.target)
		var (
			clock domain.SlaClock
			err   error
		)
		if a.command == signalCmdPauseSLA {
			clock, err = svc.PauseSla(ctx, application.PauseSlaInput{
				SignalID: a.signal, Target: target, Reason: a.reason, Actor: actor,
			})
		} else {
			clock, err = svc.ResumeSla(ctx, application.ResumeSlaInput{
				SignalID: a.signal, Target: target, Reason: a.reason, Actor: actor,
			})
		}
		if err != nil {
			return signalCommandResult{}, err
		}
		result, err := e.postCommandResult(ctx, svc, a.command, a.signal, actor)
		if err != nil {
			return signalCommandResult{}, err
		}
		ts := string(clock.Target)
		result.Target = &ts
		return result, nil

	default:
		return signalCommandResult{}, fmt.Errorf("unknown command %q", a.command)
	}
}

// postCommandResult reads the signal's post-command state for the commands
// whose use case returns a non-signal aggregate, so the result still carries
// status/priority/version. It is a read (signals.read) and changes nothing.
func (e *cmdEnv) postCommandResult(ctx context.Context, svc *application.Service, command, signalID string, actor application.Actor) (signalCommandResult, error) {
	view, err := svc.GetSignal(ctx, application.GetSignalInput{SignalID: signalID, Actor: actor})
	if err != nil {
		return signalCommandResult{}, err
	}
	return signalCommandResult{
		ID:       view.ID,
		Command:  command,
		Status:   string(view.Status),
		Priority: string(view.Priority),
		Version:  view.Version,
	}, nil
}

// resolveSignalActor resolves the acting identity (the --as subject or the
// configured bypass principal) into the audit actor the use cases stamp.
func (e *cmdEnv) resolveSignalActor(ctx context.Context, svc *application.Service, cfg *config.Config, as string) (application.Actor, outcome) {
	actor, err := svc.ResolveActor(ctx, domain.Identity{SubjectID: signalSubject(cfg, as)})
	if err != nil {
		return application.Actor{}, applicationErrorOutcome(err)
	}
	return actor, outcome{}
}

// signalSubject returns the --as subject when supplied, else the configured
// auth.bypass_principal in the local namespace (the same convention as the
// I5a reference command).
func signalSubject(cfg *config.Config, as string) string {
	if s := strings.TrimSpace(as); s != "" {
		return s
	}
	principal := strings.TrimSpace(cfg.Auth.BypassPrincipal)
	if principal == "" {
		principal = "local-developer"
	}
	return "local::" + principal
}

// signalListResult is the machine-readable payload of a signal list page
// (mirrors the API SignalList).
type signalListResult struct {
	Data       []signalView `json:"data"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

// signalView is the machine-readable signal view (the API Signal schema,
// snake_case, stable keys). It is the payload of `signal list`/`signal show`.
type signalView struct {
	ID         string          `json:"id"`
	MatchID    string          `json:"match_id"`
	CveID      string          `json:"cve_id"`
	Priority   string          `json:"priority"`
	Status     string          `json:"status"`
	Confidence string          `json:"confidence"`
	Method     string          `json:"method"`
	Asset      signalAssetView `json:"asset"`
	Product    signalProdView  `json:"product"`
	Summary    string          `json:"summary"`
	Owner      string          `json:"owner_id,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	Version    int             `json:"version"`
	DueAt      *time.Time      `json:"due_at"`
}

// signalAssetView is the joined asset of a signal view.
type signalAssetView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Criticality string `json:"criticality"`
	Exposure    string `json:"exposure"`
}

// signalProdView is the joined product of a signal view.
type signalProdView struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// signalViews maps a page of application signal views.
func signalViews(signals []application.Signal) []signalView {
	out := make([]signalView, 0, len(signals))
	for _, s := range signals {
		out = append(out, signalViewOf(s))
	}
	return out
}

// signalViewOf maps one application signal view onto the wire shape.
func signalViewOf(s application.Signal) signalView {
	return signalView{
		ID:         s.ID,
		MatchID:    s.MatchID,
		CveID:      s.CveID,
		Priority:   string(s.Priority),
		Status:     string(s.Status),
		Confidence: string(s.Confidence),
		Method:     string(s.Method),
		Asset: signalAssetView{
			ID:          s.Asset.ID,
			Name:        s.Asset.Name,
			Type:        string(s.Asset.Type),
			Criticality: string(s.Asset.Criticality),
			Exposure:    string(s.Asset.Exposure),
		},
		Product: signalProdView{
			Vendor:  s.Product.Vendor,
			Product: s.Product.Product,
			Version: s.Product.Version,
		},
		Summary:   s.Summary,
		Owner:     s.Owner,
		CreatedAt: s.CreatedAt,
		Version:   s.Version,
		DueAt:     s.DueAt,
	}
}

// signalCommandResult is the machine-readable payload of a successful command
// (schema-stable keys, mirroring the API SignalCommandResult). The nullable
// detail fields carry only the value the command produced.
type signalCommandResult struct {
	ID       string  `json:"id"`
	Command  string  `json:"command"`
	Status   string  `json:"status"`
	Priority string  `json:"priority"`
	Version  int     `json:"version"`
	OwnerID  *string `json:"owner_id,omitempty"`
	Target   *string `json:"target,omitempty"`
	AutoPrio *string `json:"auto_priority,omitempty"`
}

// signalCommandResultOf maps a post-command signal aggregate onto the wire
// result.
func signalCommandResultOf(command string, sig domain.RiskSignal, owner *string, target *domain.SLATarget, auto *domain.Priority) signalCommandResult {
	result := signalCommandResult{
		ID:       sig.ID,
		Command:  command,
		Status:   string(sig.Status),
		Priority: string(sig.Priority),
		Version:  sig.Version,
		OwnerID:  owner,
	}
	if target != nil {
		t := string(*target)
		result.Target = &t
	}
	if auto != nil {
		a := string(*auto)
		result.AutoPrio = &a
	}
	return result
}

// printSignalCommand renders a command outcome as human-readable text.
func printSignalCommand(w io.Writer, r signalCommandResult) {
	extra := ""
	if r.OwnerID != nil {
		if *r.OwnerID == "" {
			extra = ", owner cleared"
		} else {
			extra = fmt.Sprintf(", owner %s", *r.OwnerID)
		}
	}
	if r.Target != nil {
		extra += fmt.Sprintf(", target %s", *r.Target)
	}
	fmt.Fprintf(w, "signal %s: %s applied — status %s, priority %s, version %d%s\n",
		r.ID, r.Command, r.Status, r.Priority, r.Version, extra)
}

// printSignalList renders one page of the working list.
func printSignalList(w io.Writer, r signalListResult) {
	fmt.Fprintf(w, "%d signal(s):\n", len(r.Data))
	for _, s := range r.Data {
		owner := s.Owner
		if owner == "" {
			owner = "-"
		}
		fmt.Fprintf(w, "  %s %s %s owner=%s version=%d\n", s.ID, s.Priority, s.Status, owner, s.Version)
	}
	if r.NextCursor != "" {
		fmt.Fprintf(w, "next_cursor: %s\n", r.NextCursor)
	}
}

// printSignalShow renders one signal detail view.
func printSignalShow(w io.Writer, s signalView) {
	fmt.Fprintf(w, "signal %s\n", s.ID)
	fmt.Fprintf(w, "  status: %s, priority: %s, version: %d\n", s.Status, s.Priority, s.Version)
	fmt.Fprintf(w, "  cve: %s, confidence: %s, method: %s\n", s.CveID, s.Confidence, s.Method)
	fmt.Fprintf(w, "  asset: %s (%s, %s, %s)\n", s.Asset.Name, s.Asset.Type, s.Asset.Criticality, s.Asset.Exposure)
	fmt.Fprintf(w, "  product: %s/%s %s\n", s.Product.Vendor, s.Product.Product, s.Product.Version)
	if s.Owner != "" {
		fmt.Fprintf(w, "  owner: %s\n", s.Owner)
	}
	fmt.Fprintf(w, "  summary: %s\n", s.Summary)
}

// flagParseOutcome maps a flag-parse error onto the CLI verdict: a help
// request is a zero outcome (usage already printed), anything else a
// validation failure.
func flagParseOutcome(e *cmdEnv, err error) outcome {
	if errors.Is(err, flag.ErrHelp) {
		return outcome{}
	}
	return e.fail(exitValidation, classValidation, "%v", err)
}

// applicationErrorOutcome maps the use-case error classes onto the CLI
// exit-code contract (ch. 11.3): a validation mistake is exit 2, a denied
// permission exit 4 (authorisation), a state conflict exit 5, infrastructure
// trouble exit 6 and any other (unknown resource, unexpected) the generic
// exit 1. It is the same mapping the API endpoints apply (400/403/404/409),
// so every channel classifies a denial identically (NFR-013).
func applicationErrorOutcome(err error) outcome {
	switch kind, _ := application.ErrorKindOf(err); kind {
	case application.KindValidation:
		return outcome{code: exitValidation, class: classValidation, message: err.Error()}
	case application.KindForbidden:
		return outcome{code: exitAuthorisation, class: classAuthorisation, message: err.Error()}
	case application.KindConflict:
		return outcome{code: exitConflict, class: classConflict, message: err.Error()}
	case application.KindInfra:
		return outcome{code: exitInfrastructure, class: classInfrastructure, message: err.Error()}
	default: // KindNotFound and anything unknown
		return outcome{code: exitGeneric, class: classGeneric, message: err.Error()}
	}
}
