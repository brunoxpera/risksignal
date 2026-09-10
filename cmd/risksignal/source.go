// source subcommands (WP-2.08/DEV-042 + WP-2.08b/DEV-043, ARCH-002 §5):
// `source run` is the operator's manual trigger of the source.run loop — it
// enqueues one source.fetch job (dedupe key source_id + request_id) so the
// background worker's relay picks it up on its next drain and runs the
// fetch half of the source, bypassing the schedule. The command is strictly
// an enqueuer: it writes one outbox row on the database the worker shares
// and returns; the worker process delivers the job (a manual trigger is
// idempotent per request id — a repeated run with the same id enqueues
// nothing new, a fresh id always enqueues a fresh job).
//
// `source list` and `source status` (DEV-043) render the source monitor
// projection — the read-only view of ARCH-002 §5; they live in
// source_monitor.go.
//
// Composition: cmd/risksignal is the composition root of the command path.
// It opens the pool, wires the postgres repositories behind the application
// ports (dbService) and resolves the source row the command names — by id,
// or by its type when exactly one source of that type is registered — with
// the sqlc query set directly (an operator resolution read, not a domain
// command, following the demo seed convention).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// sourceCommandTimeout bounds one source command. Enqueuing is a single
// outbox append; the bound keeps automation from hanging on a stalled
// database (same convention as the demo commands).
const sourceCommandTimeout = 5 * time.Minute

// runSource dispatches `risksignal source ...`: the manual run trigger
// (run) and the monitor surface (list, status — DEV-043, ARCH-002 §5).
func runSource(e *cmdEnv, args []string) int {
	if len(args) < 1 {
		return e.emit("source", e.fail(exitValidation, classValidation,
			"missing subcommand (supported: run, list, status)"))
	}
	command := "source " + args[0]
	switch args[0] {
	case "run":
		return e.emit(command, e.cmdSourceRun(args[1:]))
	case "list":
		return e.emit(command, e.cmdSourceList(args[1:]))
	case "status":
		return e.emit(command, e.cmdSourceStatus(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation,
			"unknown subcommand (supported: run, list, status)"))
	}
}

// cmdSourceRun enqueues one manual source.fetch job for the named source
// (ARCH-002 §5): <source> is the source's id or its type ("nvd", "kev",
// "epss") when exactly one source of that type is registered. Without
// --request-id every invocation gets a fresh request id and enqueues a new
// job; a fixed --request-id makes the trigger idempotent (the same request
// id enqueues nothing twice — the outbox dedupe key is source_id +
// request_id). The worker delivers the job; nothing here runs a fetch.
func (e *cmdEnv) cmdSourceRun(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal source run <type|id> [--request-id <id>]\n"+
		"  --request-id <id>  idempotency key of the manual run (default: a fresh id\n"+
		"                     per invocation — every run enqueues a new job)")
	requestID := fs.String("request-id", "", "idempotency key of the manual run (default: a fresh id per invocation)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() != 1 {
		return e.fail(exitValidation, classValidation,
			"source run takes exactly one argument: the source id or its type (run 'risksignal help' for usage)")
	}
	ref := fs.Arg(0)

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	ctx, cancel := context.WithTimeout(context.Background(), sourceCommandTimeout)
	defer cancel()

	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()
	q := gen.New(pool)

	sourceID, err := resolveSourceRef(ctx, q, ref)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return e.fail(exitGeneric, classGeneric, "no source with id %q registered", ref)
		}
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}

	reqID := *requestID
	if reqID == "" {
		reqID = uuid.New()
	}
	res, err := svc.EnqueueManualSourceFetch(ctx, application.EnqueueManualSourceFetchInput{
		SourceID:  sourceID,
		RequestID: reqID,
	})
	if err != nil {
		return demoErrorOutcome(err)
	}

	if e.format == formatText {
		if res.AlreadyQueued {
			fmt.Fprintf(e.stdout, "source.fetch job already queued for source %s (%s) — request %s (dedupe %s)\n",
				res.SourceType, res.SourceID, res.RequestID, res.DedupeKey)
		} else {
			fmt.Fprintf(e.stdout, "enqueued source.fetch job for source %s (%s) — request %s (dedupe %s); the worker runs the fetch on its next drain\n",
				res.SourceType, res.SourceID, res.RequestID, res.DedupeKey)
		}
	}
	return e.ok(sourceRunResult{
		SourceID:      res.SourceID,
		SourceType:    string(res.SourceType),
		RequestID:     res.RequestID,
		DedupeKey:     res.DedupeKey,
		AlreadyQueued: res.AlreadyQueued,
	})
}

// sourceRunResult is the machine-readable payload of source run: the
// enqueued job's identity and dedupe key. AlreadyQueued is true when a job
// with the same request id was already in the outbox.
type sourceRunResult struct {
	SourceID      string `json:"source_id"`
	SourceType    string `json:"source_type"`
	RequestID     string `json:"request_id"`
	DedupeKey     string `json:"dedupe_key"`
	AlreadyQueued bool   `json:"already_queued"`
}

// resolveSourceRef resolves the source a command names: a syntactically
// valid uuid is read by id; anything else is treated as a source type and
// must name exactly one registered source row (a type shared by several
// rows is ambiguous and rejected — the rows are unique by (type, name), so
// an operator naming a type needs the id to disambiguate).
func resolveSourceRef(ctx context.Context, q *gen.Queries, ref string) (string, error) {
	var id pgtype.UUID
	if err := id.Scan(ref); err == nil {
		row, err := q.GetSourceByID(ctx, id)
		if err != nil {
			return "", err
		}
		return demoUUID(row.ID), nil
	}

	rows, err := q.ListSourcesByType(ctx, ref)
	if err != nil {
		return "", err
	}
	switch len(rows) {
	case 0:
		return "", fmt.Errorf("no source of type %q registered", ref)
	case 1:
		return demoUUID(rows[0].ID), nil
	default:
		names := ""
		for i, row := range rows {
			if i > 0 {
				names += ", "
			}
			names += fmt.Sprintf("%s (%s)", row.Name, demoUUID(row.ID))
		}
		return "", fmt.Errorf("source type %q matches %d sources — pass the source id: %s", ref, len(rows), names)
	}
}
