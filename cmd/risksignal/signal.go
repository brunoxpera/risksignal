// `risksignal signal command` (concept ch. 11.3, ARCH-005 §8, WP-5a.08): the
// CLI form of the I5a reference triage operation. It drives the same
// application use cases as the API endpoint
//
//	POST /api/v1/signals/{signal_id}/commands
//
// with the same in-command permission gates and the same audit — the
// application layer is the gate of record, so no channel bypasses it
// (ARCH-005 §5, NFR-013 channel parity).
//
// The command is strictly non-interactive (ch. 11.3): the signal id, the
// command and its parameters are complete command-line arguments, never a
// terminal dialogue. The acting identity is selected with --as (an
// issuer-qualified subject, e.g. "local::security-analyst"); it defaults to
// the configured auth.bypass_principal in the local namespace. In production
// the subject comes from the CLI's OIDC login (I5b); --as only names which
// seeded/dev identity acts.

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

// signalCommandTimeout bounds one command run; the command is a single read +
// one guarded write, so the bound only protects automation from a hanging
// database.
const signalCommandTimeout = 30 * time.Second

// The two I5a reference commands (the API enum, mirrored for the CLI).
const (
	signalCmdAcknowledge      = "acknowledge"
	signalCmdOverridePriority = "override_priority"
)

// runSignal dispatches `risksignal signal <subcommand>`.
func runSignal(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.emit("signal", e.fail(exitValidation, classValidation, "missing subcommand (supported: acknowledge, override)"))
	}
	command := "signal " + args[0]
	switch args[0] {
	case "acknowledge":
		return e.emit(command, e.cmdSignalAcknowledge(args[1:]))
	case "override":
		return e.emit(command, e.cmdSignalOverride(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation, "unknown subcommand (supported: acknowledge, override)"))
	}
}

// cmdSignalAcknowledge runs `risksignal signal acknowledge --signal <id>
// --version <n> [--as <subject>]`.
func (e *cmdEnv) cmdSignalAcknowledge(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal acknowledge --signal <id> --version <n> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to acknowledge (mandatory)")
	version := fs.Int("version", 0, "optimistic-lock version (mandatory, >= 1)")
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
	return e.runSignalCommand(signalCommandArgs{
		command: signalCmdAcknowledge,
		signal:  *signal,
		version: *version,
		as:      *as,
	})
}

// cmdSignalOverride runs `risksignal signal override --signal <id>
// --priority <P1..P4> --reason <text> --version <n> [--as <subject>]`.
func (e *cmdEnv) cmdSignalOverride(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal signal override --signal <id> --priority <P1..P4> --reason <text> --version <n> [--as <subject>]")
	signal := fs.String("signal", "", "signal id to override (mandatory)")
	priority := fs.String("priority", "", "new effective priority, P1..P4 (mandatory)")
	reason := fs.String("reason", "", "mandatory, non-blank justification")
	version := fs.Int("version", 0, "optimistic-lock version (mandatory, >= 1)")
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
	return e.runSignalCommand(signalCommandArgs{
		command:  signalCmdOverridePriority,
		signal:   *signal,
		priority: *priority,
		reason:   *reason,
		version:  *version,
		as:       *as,
	})
}

// signalCommandArgs carries the validated-on-entry arguments of one reference
// command run.
type signalCommandArgs struct {
	command  string
	signal   string
	priority string
	reason   string
	version  int
	as       string
}

// runSignalCommand resolves the acting identity and drives the reference use
// case, mapping its error classes onto the CLI exit-code contract.
func (e *cmdEnv) runSignalCommand(a signalCommandArgs) outcome {
	if strings.TrimSpace(a.signal) == "" {
		return e.fail(exitValidation, classValidation, "--signal is mandatory (the signal id)")
	}
	if a.version < 1 {
		return e.fail(exitValidation, classValidation, "--version is mandatory and must be >= 1")
	}
	if a.command == signalCmdOverridePriority {
		if strings.TrimSpace(a.priority) == "" {
			return e.fail(exitValidation, classValidation, "--priority is mandatory for override")
		}
		if strings.TrimSpace(a.reason) == "" {
			return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank for override")
		}
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	subject := strings.TrimSpace(a.as)
	if subject == "" {
		principal := strings.TrimSpace(cfg.Auth.BypassPrincipal)
		if principal == "" {
			principal = "local-developer"
		}
		subject = "local::" + principal
	}

	ctx, cancel := context.WithTimeout(context.Background(), signalCommandTimeout)
	defer cancel()

	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	actor, err := svc.ResolveActor(ctx, domain.Identity{SubjectID: subject})
	if err != nil {
		return signalCommandErrorOutcome(err)
	}

	var sig domain.RiskSignal
	switch a.command {
	case signalCmdAcknowledge:
		sig, err = svc.AcknowledgeSignal(ctx, application.AcknowledgeSignalInput{
			SignalID: a.signal, ExpectedVersion: a.version, Actor: actor,
		})
	case signalCmdOverridePriority:
		sig, err = svc.OverridePriority(ctx, application.OverridePriorityInput{
			SignalID: a.signal, Priority: domain.Priority(a.priority), Reason: a.reason,
			ExpectedVersion: a.version, Actor: actor,
		})
	default:
		return e.fail(exitValidation, classValidation, "unknown command %q", a.command)
	}
	if err != nil {
		return signalCommandErrorOutcome(err)
	}

	payload := signalCommandResult{
		ID:       sig.ID,
		Command:  a.command,
		Status:   string(sig.Status),
		Priority: string(sig.Priority),
		Version:  sig.Version,
	}
	if e.format == formatText {
		printSignalCommand(e.stdout, payload)
	}
	return e.ok(payload)
}

// signalCommandResult is the machine-readable payload of a successful
// reference command (schema-stable keys, mirroring the API result).
type signalCommandResult struct {
	ID       string `json:"id"`
	Command  string `json:"command"`
	Status   string `json:"status"`
	Priority string `json:"priority"`
	Version  int    `json:"version"`
}

// printSignalCommand renders the outcome as human-readable text.
func printSignalCommand(w io.Writer, r signalCommandResult) {
	fmt.Fprintf(w, "signal %s: %s applied — status %s, priority %s, version %d\n",
		r.ID, r.Command, r.Status, r.Priority, r.Version)
}

// signalCommandErrorOutcome maps the use-case error classes onto the CLI
// exit-code contract (ch. 11.3): a validation mistake is exit 2, a denied
// permission exit 4 (authorisation), a state conflict exit 5, infrastructure
// trouble exit 6 and any other (unknown signal, unexpected) the generic
// exit 1. It is the same mapping the API endpoint applies (400/403/409/500),
// so both channels classify a denial identically (NFR-013).
func signalCommandErrorOutcome(err error) outcome {
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
