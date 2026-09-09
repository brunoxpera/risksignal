// quarantine subcommands (WP-2.09 / DEV-035, ARCH-002 §4, concept ch. 8.6
// and 11.3): `quarantine list` renders the quarantine working list — the
// records the I2 normalisers isolated because they failed to parse or
// normalise (position, reason, payload hash, status, created_at, source) —
// and `quarantine ack <id> --note "…"` records the operator review
// (new -> acknowledged, ARCH-002 §4) with the reviewer and the note.
// `quarantine reprocess <id>` lives in this file below the ack handler
// (DEV-035 commit 2): it re-reads the raw record the row was isolated
// from and re-runs the source's normaliser at the current adapter.
//
// Every state change of the machine is a domain command of the application
// service (QuarantineAck / QuarantineReprocess, DEV-030): the command runs
// one transaction (postgres.WithTx) in which the state change and its audit
// event commit or roll back together (ch. 5.1 "one domain command, one
// transaction", ch. 13.2 — every quarantine transition is auditable).
//
// The working-list read is an operator read on the sqlc query set (the
// quarantine rows joined with their source type/name) — the same
// convention as the source monitor projection (source_monitor.go): a read
// that renders the stored timestamps (created_at …) and the source
// attribution of every row, not a domain command.
//
// Composition: cmd/risksignal is the composition root of the command path
// (dbService in demo.go wires the postgres repositories behind the
// application ports). The audit actor of the review commands is the I2
// system principal "operator" (application.defaultQuarantineActorID) —
// user principals arrive with I5a, ch. 13.2; the commands take no identity
// input and never prompt.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// quarantineCommandTimeout bounds one quarantine command. Ack/reprocess run
// one transaction plus their reads; the bound keeps automation from hanging
// on a stalled database (same convention as the demo and source commands).
const quarantineCommandTimeout = 5 * time.Minute

// defaultQuarantineListLimit is the page size of `quarantine list` without
// an explicit --limit: the working list is bounded, the operator raises the
// limit for a full dump.
const defaultQuarantineListLimit = 100

// runQuarantine dispatches `risksignal quarantine ...`: the working list
// (list), the operator review (ack) and the reprocess command
// (DEV-035 commit 2). Missing or unknown subcommands are validation
// failures (exit 2) reported before any configuration load.
func runQuarantine(e *cmdEnv, args []string) int {
	if len(args) < 1 {
		return e.emit("quarantine", e.fail(exitValidation, classValidation,
			"missing subcommand (supported: list, ack)"))
	}
	command := "quarantine " + args[0]
	switch args[0] {
	case "list":
		return e.emit(command, e.cmdQuarantineList(args[1:]))
	case "ack":
		return e.emit(command, e.cmdQuarantineAck(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation,
			"unknown subcommand (supported: list, ack)"))
	}
}

// quarantineView is the operator-visible state of one quarantine row
// (ARCH-002 §3/§4): the isolation facts (source, position, reason, payload
// hash), the machine state (status, attempts) and the review/resolution
// records. The JSON shape is fixed: absent facts render as empty strings,
// never as missing keys, and every timestamp is RFC 3339 UTC. The view is
// rendered from the stored row — the CLI never fabricates a field the
// database does not carry.
type quarantineView struct {
	ID          string `json:"id"`
	SourceID    string `json:"source_id"`
	SourceType  string `json:"source_type"`
	SourceName  string `json:"source_name"`
	Position    string `json:"position"`
	Reason      string `json:"reason"`
	PayloadHash string `json:"payload_hash"`
	Status      string `json:"status"`
	Attempts    int    `json:"attempts"`
	CreatedAt   string `json:"created_at"`

	// Review records (new -> acknowledged, ARCH-002 §4).
	AcknowledgedBy   string `json:"acknowledged_by"`
	AcknowledgedNote string `json:"acknowledged_note"`
	AcknowledgedAt   string `json:"acknowledged_at"`

	// Resolution records (-> resolved; the links to the new domain object).
	ResolvedVulnerabilityID string `json:"resolved_vulnerability_id"`
	ResolvedEvidenceID      string `json:"resolved_evidence_id"`
	ResolvedNote            string `json:"resolved_note"`
	ResolvedAt              string `json:"resolved_at"`
}

// quarantineListResult is the machine-readable payload of `quarantine
// list`: the ordered working-list rows (oldest isolation first, ARCH-002
// §4) with the fixed quarantineView shape per row.
type quarantineListResult struct {
	Quarantine []quarantineView `json:"quarantine"`
}

// cmdQuarantineList renders the quarantine working list (ARCH-002 §4,
// ch. 11.3): every isolated row ordered by created_at then id, optionally
// filtered by status (new | acknowledged | ready_for_retry | resolved) and
// by source (the source id, or its type when exactly one source of that
// type is registered — the resolution of `source run`). The row carries
// position, reason, payload hash, status, created_at and the source
// attribution (id, type, name) — the isolation facts the operator reviews
// — plus the attempts counter and the review/resolution records.
func (e *cmdEnv) cmdQuarantineList(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal quarantine list [--status <status>] [--source <type|id>] [--limit <n>]\n"+
		"  --status <status>   filter by quarantine status: new, acknowledged, ready_for_retry, resolved\n"+
		"  --source <type|id>  filter by the source that isolated the row (id, or type when unambiguous)\n"+
		"  --limit <n>         page size (default: 100)")
	statusText := fs.String("status", "", "quarantine status filter")
	sourceRef := fs.String("source", "", "source id or type filter")
	limit := fs.Int("limit", defaultQuarantineListLimit, "page size")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	var status *domain.QuarantineStatus
	if *statusText != "" {
		parsed, err := domain.ParseQuarantineStatus(*statusText)
		if err != nil {
			return e.fail(exitValidation, classValidation, "--status: %v (supported: new, acknowledged, ready_for_retry, resolved)", err)
		}
		status = &parsed
	}
	if *limit < 1 {
		return e.fail(exitValidation, classValidation, "--limit must be >= 1")
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), quarantineCommandTimeout)
	defer cancel()

	pool, _, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()
	q := gen.New(pool)

	// The optional source filter names a source id or its type (resolved
	// by the `source run` convention); an unresolvable ref is a generic
	// failure naming the ref, not a validation mistake of the flag.
	var sourceID string
	if *sourceRef != "" {
		id, err := resolveSourceRef(ctx, q, *sourceRef)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return e.fail(exitGeneric, classGeneric, "no source with id %q registered", *sourceRef)
			}
			return e.fail(exitGeneric, classGeneric, "%v", err)
		}
		sourceID = id
	}

	rows, err := loadQuarantineRows(ctx, q, status, sourceID, *limit)
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}
	if e.format == formatText {
		printQuarantineList(e.stdout, rows)
	}
	return e.ok(quarantineListResult{Quarantine: rows})
}

// loadQuarantineRows is the operator read of the working list: the
// quarantine rows (ListQuarantine, filters + page size) joined in Go with
// the source type/name of every row (ListSources). A corrupt or
// unreachable database read is returned as-is for the caller to classify.
func loadQuarantineRows(ctx context.Context, q *gen.Queries, status *domain.QuarantineStatus, sourceID string, limit int) ([]quarantineView, error) {
	sources, err := q.ListSources(ctx)
	if err != nil {
		return nil, err
	}
	srcType := make(map[string]string, len(sources)) // source id -> type
	srcName := make(map[string]string, len(sources)) // source id -> name
	for _, src := range sources {
		id := demoUUID(src.ID)
		srcType[id] = src.Type
		srcName[id] = src.Name
	}

	statusFilter := pgtype.Text{}
	if status != nil {
		statusFilter = pgtype.Text{String: string(*status), Valid: true}
	}
	sourceFilter, err := optUUID(sourceID)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListQuarantine(ctx, gen.ListQuarantineParams{
		Status:   statusFilter,
		SourceID: sourceFilter,
		MaxRows:  int32(limit),
	})
	if err != nil {
		return nil, err
	}
	views := make([]quarantineView, 0, len(rows))
	for _, row := range rows {
		views = append(views, quarantineRowView(row, srcType[demoUUID(row.SourceID)], srcName[demoUUID(row.SourceID)]))
	}
	return views, nil
}

// quarantineRowView maps one stored quarantine row onto the operator view.
func quarantineRowView(row gen.Quarantine, sourceType, sourceName string) quarantineView {
	return quarantineView{
		ID:          demoUUID(row.ID),
		SourceID:    demoUUID(row.SourceID),
		SourceType:  sourceType,
		SourceName:  sourceName,
		Position:    row.Position,
		Reason:      row.Reason,
		PayloadHash: row.PayloadHash,
		Status:      row.Status,
		Attempts:    int(row.Attempts),
		CreatedAt:   tsText(row.CreatedAt),

		AcknowledgedBy:   row.AcknowledgedBy.String,
		AcknowledgedNote: row.AcknowledgedNote.String,
		AcknowledgedAt:   tsText(row.AcknowledgedAt),

		ResolvedVulnerabilityID: demoUUID(row.ResolvedVulnerabilityID),
		ResolvedEvidenceID:      demoUUID(row.ResolvedEvidenceID),
		ResolvedNote:            row.ResolvedNote.String,
		ResolvedAt:              tsText(row.ResolvedAt),
	}
}

// cmdQuarantineAck records the operator review of one isolated record
// (new -> acknowledged, ARCH-002 §4): the state change and its
// quarantine.acknowledged audit event are written atomically by the
// QuarantineAck use case (one command, one transaction, ch. 5.1). The
// review note arrives through --note; the audit actor is the I2 system
// principal "operator" (no user principals before I5a, ch. 13.2) — the
// use case records it as acknowledged_by. The machine's guards are
// enforced by the domain transition and the SQL guard (status = 'new'): an
// already reviewed, retryable or resolved row is rejected (exit 2) without
// a write and without an audit event.
func (e *cmdEnv) cmdQuarantineAck(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal quarantine ack <id> [--note <text>]\n"+
		"  --note <text>  review note recorded with the acknowledgement")
	note := fs.String("note", "", "review note of the acknowledgement")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() != 1 {
		return e.fail(exitValidation, classValidation,
			"quarantine ack takes exactly one argument: the quarantine id")
	}
	id := fs.Arg(0)

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), quarantineCommandTimeout)
	defer cancel()

	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()
	q := gen.New(pool)

	// Pre-read: fail fast with a message naming the id on an unknown row
	// and resolve the source attribution for the result view.
	row, out := readQuarantineRow(ctx, q, id)
	if !out.ok() {
		return out
	}
	view, out := e.quarantineViewOf(ctx, q, row)
	if !out.ok() {
		return out
	}

	if _, err := svc.QuarantineAck(ctx, application.QuarantineAckInput{
		ID:   id,
		Note: *note,
		// Actor is empty: the use case defaults to the I2 system
		// principal "operator" (application.defaultQuarantineActorID).
	}); err != nil {
		return demoErrorOutcome(err)
	}

	// Render the committed state (the authoritative row after the write,
	// timestamps included — the use case result carries the domain view).
	committed, out := readQuarantineRow(ctx, q, id)
	if !out.ok() {
		return out
	}
	committedView := quarantineRowView(committed, view.SourceType, view.SourceName)

	if e.format == formatText {
		printQuarantineAck(e.stdout, committedView)
	}
	return e.ok(committedView)
}

// readQuarantineRow loads one quarantine row by its id — the pre-read of
// the review/reprocess commands. A syntactically invalid id is a
// validation failure; an unknown id a generic failure naming the id (the
// convention of `source run`); a database failure is infrastructure.
func readQuarantineRow(ctx context.Context, q *gen.Queries, id string) (gen.Quarantine, outcome) {
	var qid pgtype.UUID
	if err := qid.Scan(id); err != nil {
		return gen.Quarantine{}, outcome{code: exitValidation, class: classValidation,
			message: fmt.Sprintf("invalid quarantine id %q", id)}
	}
	row, err := q.GetQuarantineByID(ctx, qid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return gen.Quarantine{}, outcome{code: exitGeneric, class: classGeneric,
				message: fmt.Sprintf("no quarantine row with id %q", id)}
		}
		return gen.Quarantine{}, outcome{code: exitInfrastructure, class: classInfrastructure,
			message: err.Error()}
	}
	return row, outcome{}
}

// quarantineViewOf resolves the source attribution of one stored row (its
// sources row: type + name) and renders the operator view.
func (e *cmdEnv) quarantineViewOf(ctx context.Context, q *gen.Queries, row gen.Quarantine) (quarantineView, outcome) {
	src, err := q.GetSourceByID(ctx, row.SourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return quarantineView{}, outcome{code: exitGeneric, class: classGeneric,
				message: fmt.Sprintf("quarantine %s references unknown source %s", demoUUID(row.ID), demoUUID(row.SourceID))}
		}
		return quarantineView{}, outcome{code: exitInfrastructure, class: classInfrastructure,
			message: err.Error()}
	}
	return quarantineRowView(row, src.Type, src.Name), outcome{}
}

// tsText renders a stored timestamp as RFC 3339 UTC; an absent timestamp
// (the column is NULL) renders as "".
func tsText(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ""
	}
	return t.Time.UTC().Format(time.RFC3339)
}

// optUUID parses an optional canonical uuid string; "" maps onto the
// invalid pgtype.UUID that stores/open-filters NULL (the convention of
// repo.dbmap.optUUID, which is unexported).
func optUUID(s string) (pgtype.UUID, error) {
	if s == "" {
		return pgtype.UUID{}, nil
	}
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}

// printQuarantineList renders the working list as one block per row:
// the isolation facts (source, position, reason, payload hash), the
// machine state and the created_at instant.
func printQuarantineList(w io.Writer, rows []quarantineView) {
	fmt.Fprintf(w, "quarantine list: %d row(s)\n", len(rows))
	for _, row := range rows {
		fmt.Fprintf(w, "%s / %s (id %s): %s, attempts %d, position %s, created %s\n",
			row.SourceType, row.SourceName, row.SourceID, row.Status, row.Attempts, row.Position, row.CreatedAt)
		fmt.Fprintf(w, "  id %s; reason: %s\n", row.ID, row.Reason)
		fmt.Fprintf(w, "  payload_hash: %s\n", row.PayloadHash)
	}
}

// printQuarantineAck renders the acknowledgement outcome: the committed
// row state with the review records (reviewer, note, acknowledged_at).
func printQuarantineAck(w io.Writer, row quarantineView) {
	fmt.Fprintf(w, "quarantine %s acknowledged: status %s, by %s at %s\n",
		row.ID, row.Status, row.AcknowledgedBy, row.AcknowledgedAt)
	if row.AcknowledgedNote != "" {
		fmt.Fprintf(w, "  note: %s\n", row.AcknowledgedNote)
	}
}
