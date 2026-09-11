// `risksignal legal-hold ...` (concept ch. 11.3, ARCH-007 §2.1, WP-6.07 /
// DEV-119): the CLI form of the legal-hold surface. It drives the same
// application use cases as the API endpoints
//
//	POST /api/v1/legal-holds
//	GET  /api/v1/legal-holds
//	POST /api/v1/legal-holds/{id}/release
//
// with the same in-command gate (retention.manage, deny-by-default) and the
// same audit — the application layer is the gate of record, so no channel
// bypasses it (ARCH-005 §5, NFR-013 channel parity). The command vocabulary is
// 1:1 with the API:
//
//	risksignal legal-hold create  --aggregate <id> [--aggregate-type <t>] --reason <t> [--as]
//	risksignal legal-hold release --hold <id> --reason <t> --yes [--as]
//	risksignal legal-hold list    [--aggregate <id>] [--aggregate-type <t>] [--active] [--as]
//
// The commands are strictly non-interactive (ch. 11.3): the aggregate, the hold
// id and the documented reason are complete command-line arguments, never a
// terminal dialogue. `legal-hold release` weakens the protection (it lets a
// retention run delete or pseudonymise the aggregate again), so it is treated
// as destructive and requires the explicit --yes confirmation flag. The acting
// identity is selected with --as; it defaults to the configured
// auth.bypass_principal in the local namespace.

package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
)

// legalHoldCommandTimeout bounds one legal-hold command: a read plus at most
// one guarded transaction.
const legalHoldCommandTimeout = 30 * time.Second

// legalHoldSubcommands lists the supported subcommands for the error message.
const legalHoldSubcommands = "create, release, list"

// runLegalHold dispatches `risksignal legal-hold <subcommand>`.
func runLegalHold(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.emit("legal-hold", e.fail(exitValidation, classValidation, "missing subcommand (supported: %s)", legalHoldSubcommands))
	}
	command := "legal-hold " + args[0]
	switch args[0] {
	case "create":
		return e.emit(command, e.cmdLegalHoldCreate(args[1:]))
	case "release":
		return e.emit(command, e.cmdLegalHoldRelease(args[1:]))
	case "list":
		return e.emit(command, e.cmdLegalHoldList(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation, "unknown subcommand (supported: %s)", legalHoldSubcommands))
	}
}

// cmdLegalHoldCreate runs `risksignal legal-hold create --aggregate <id>
// [--aggregate-type <t>] --reason <t> [--as <subject>]`.
func (e *cmdEnv) cmdLegalHoldCreate(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal legal-hold create --aggregate <id> [--aggregate-type <t>] --reason <text> [--as <subject>]")
	aggregate := fs.String("aggregate", "", "aggregate id to hold (mandatory)")
	aggregateType := fs.String("aggregate-type", "", "aggregate type (default risk_signal)")
	reason := fs.String("reason", "", "documented hold reason (mandatory, non-blank)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*aggregate) == "" {
		return e.fail(exitValidation, classValidation, "--aggregate is mandatory (the aggregate id to hold)")
	}
	if strings.TrimSpace(*reason) == "" {
		return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), legalHoldCommandTimeout)
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
	hold, err := svc.CreateLegalHold(ctx, application.CreateLegalHoldInput{
		AggregateType: strings.TrimSpace(*aggregateType),
		AggregateID:   *aggregate,
		Reason:        *reason,
		Actor:         actor,
	})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	view := legalHoldViewOf(hold)
	if e.format == formatText {
		fmt.Fprintf(e.stdout, "legal hold %s: set on %s/%s\n", view.ID, view.AggregateType, view.AggregateID)
	}
	return e.ok(view)
}

// cmdLegalHoldRelease runs `risksignal legal-hold release --hold <id>
// --reason <t> --yes [--as <subject>]`.
func (e *cmdEnv) cmdLegalHoldRelease(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal legal-hold release --hold <id> --reason <text> --yes [--as <subject>]")
	hold := fs.String("hold", "", "legal hold id to release (mandatory)")
	reason := fs.String("reason", "", "documented release reason (mandatory, non-blank)")
	yes := fs.Bool("yes", false, "confirm the destructive release (mandatory)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*hold) == "" {
		return e.fail(exitValidation, classValidation, "--hold is mandatory (the legal hold id to release)")
	}
	if strings.TrimSpace(*reason) == "" {
		return e.fail(exitValidation, classValidation, "--reason is mandatory and must not be blank")
	}
	if !*yes {
		return e.fail(exitValidation, classValidation, "legal-hold release is destructive; pass --yes to confirm (the CLI never prompts)")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), legalHoldCommandTimeout)
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
	released, err := svc.ReleaseLegalHold(ctx, application.ReleaseLegalHoldInput{HoldID: *hold, Reason: *reason, Actor: actor})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	view := legalHoldViewOf(released)
	if e.format == formatText {
		fmt.Fprintf(e.stdout, "legal hold %s: released\n", view.ID)
	}
	return e.ok(view)
}

// cmdLegalHoldList runs `risksignal legal-hold list [--aggregate <id>]
// [--aggregate-type <t>] [--active] [--as <subject>]`.
func (e *cmdEnv) cmdLegalHoldList(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal legal-hold list [--aggregate <id>] [--aggregate-type <t>] [--active] [--as <subject>]")
	aggregate := fs.String("aggregate", "", "filter by aggregate id")
	aggregateType := fs.String("aggregate-type", "", "filter by aggregate type")
	active := fs.Bool("active", false, "only active holds (default: all holds, active and released)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), legalHoldCommandTimeout)
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
	in := application.ListLegalHoldsInput{
		AggregateType: strings.TrimSpace(*aggregateType),
		AggregateID:   strings.TrimSpace(*aggregate),
		Actor:         actor,
	}
	if *active {
		t := true
		in.Active = &t
	}
	holds, err := svc.ListLegalHolds(ctx, in)
	if err != nil {
		return applicationErrorOutcome(err)
	}
	views := make([]legalHoldView, 0, len(holds))
	for _, h := range holds {
		views = append(views, legalHoldViewOf(h))
	}
	result := legalHoldListResult{Data: views}
	if e.format == formatText {
		printLegalHoldList(e.stdout, result)
	}
	return e.ok(result)
}

// legalHoldListResult is the machine-readable legal-hold page (mirrors the API
// LegalHoldList).
type legalHoldListResult struct {
	Data []legalHoldView `json:"data"`
}

// legalHoldView is the machine-readable legal hold (the API LegalHold schema,
// snake_case, stable keys).
type legalHoldView struct {
	ID            string     `json:"id"`
	AggregateType string     `json:"aggregate_type"`
	AggregateID   string     `json:"aggregate_id"`
	Reason        string     `json:"reason"`
	ActorID       string     `json:"actor_id"`
	CreatedAt     time.Time  `json:"created_at"`
	ReleasedAt    *time.Time `json:"released_at"`
}

// legalHoldViewOf maps a stored legal hold onto the wire view.
func legalHoldViewOf(h application.LegalHold) legalHoldView {
	view := legalHoldView{
		ID:            h.ID,
		AggregateType: h.AggregateType,
		AggregateID:   h.AggregateID,
		Reason:        h.Reason,
		ActorID:       h.ActorID,
		CreatedAt:     h.CreatedAt,
	}
	if !h.ReleasedAt.IsZero() {
		at := h.ReleasedAt
		view.ReleasedAt = &at
	}
	return view
}

// printLegalHoldList renders the legal-hold list as human-readable text.
func printLegalHoldList(w io.Writer, r legalHoldListResult) {
	fmt.Fprintf(w, "%d legal hold(s):\n", len(r.Data))
	for _, h := range r.Data {
		state := "active"
		if h.ReleasedAt != nil {
			state = "released"
		}
		fmt.Fprintf(w, "  %s %s/%s [%s] reason=%q\n", h.ID, h.AggregateType, h.AggregateID, state, h.Reason)
	}
}
