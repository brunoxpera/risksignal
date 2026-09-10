// quarantine subcommands (WP-2.09 / DEV-035, ARCH-002 §4, concept ch. 8.6
// and 11.3): `quarantine list` renders the quarantine working list — the
// records the I2 normalisers isolated because they failed to parse or
// normalise (position, reason, payload hash, status, created_at, source) —
// `quarantine ack <id> --note "…"` records the operator review
// (new -> acknowledged, ARCH-002 §4) with the reviewer and the note, and
// `quarantine reprocess <id>` re-reads the raw record the row was isolated
// from and re-runs the source's normaliser at the current adapter: a clean
// pass resolves the row (-> resolved, linked to the new domain object), a
// pass that still isolates the record increments attempts and stays
// retryable (ARCH-002 §4) — both transitions audited.
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
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/epss"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/kev"
	"github.com/brunoxpera/risksignal/internal/adapters/sources/nvd"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
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
			"missing subcommand (supported: list, ack, reprocess)"))
	}
	command := "quarantine " + args[0]
	switch args[0] {
	case "list":
		return e.emit(command, e.cmdQuarantineList(args[1:]))
	case "ack":
		return e.emit(command, e.cmdQuarantineAck(args[1:]))
	case "reprocess":
		return e.emit(command, e.cmdQuarantineReprocess(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation,
			"unknown subcommand (supported: list, ack, reprocess)"))
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

// quarantineReprocessResult is the machine-readable payload of `quarantine
// reprocess <id>`: the committed row state (embedded, flattened — the same
// fixed quarantineView shape as the other commands) plus the outcome of
// the normaliser pass. Resolved is true when the pass succeeded and the
// row left the quarantine (-> resolved, linked to the new domain object);
// false when the offending record still fails to normalise — the row's
// attempts incremented and it stays retryable, which is an audited state
// change, never an error of the command.
type quarantineReprocessResult struct {
	quarantineView
	Resolved bool `json:"resolved"`
	Records  int  `json:"records"` // domain records the pass normalised
	Errors   int  `json:"errors"`  // records the pass still isolated
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
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
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
	if *limit > math.MaxInt32 {
		return e.fail(exitValidation, classValidation, "--limit is too large (max %d)", math.MaxInt32)
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
	if limit < 1 || limit > math.MaxInt32 {
		// The repo page-size parameter is int32: reject a page size the
		// conversion would wrap instead of truncating it silently (G115).
		// Callers validate the operator-facing flag already; this guard
		// keeps the boundary safe for every call path.
		return nil, fmt.Errorf("invalid quarantine page size %d (want 1..%d)", limit, math.MaxInt32)
	}
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

// cmdQuarantineReprocess re-runs the source's normaliser over the raw
// record a quarantined row was isolated from (ARCH-002 §4): the adapter of
// the row's source type (the current implementation of the source port,
// resolved by the registry below — the same composition as the worker) is
// invoked on the stored raw record bytes, streaming through the
// persistence sink on the command's transaction. A clean pass resolves the
// row — linked to the new domain object the pass materialised — with the
// quarantine.resolved audit event; a pass that still isolates the record
// increments attempts, keeps the row retryable and writes the
// quarantine.reprocessed audit event; both transitions and their audit
// events commit atomically in the QuarantineReprocess use case (one
// command, one transaction, ch. 5.1). A failed attempt is a successful
// command (exit 0, resolved false): the audited state change happened. An
// infrastructure failure of the pass rolls everything back and exits 6
// without a state change.
func (e *cmdEnv) cmdQuarantineReprocess(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal quarantine reprocess <id>")
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() != 1 {
		return e.fail(exitValidation, classValidation,
			"quarantine reprocess takes exactly one argument: the quarantine id")
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
	// and resolve the source row — its type selects the adapter to run.
	row, out := readQuarantineRow(ctx, q, id)
	if !out.ok() {
		return out
	}
	src, out := e.quarantineSourceOf(ctx, q, row)
	if !out.ok() {
		return out
	}
	adapter, ok := quarantineAdapters()[src.Type]
	if !ok {
		return e.fail(exitValidation, classValidation,
			"no source adapter registered for source type %q (quarantine %s) — the CLI can reprocess nvd, kev and epss rows",
			src.Type, rowViewID(row))
	}

	result, err := svc.QuarantineReprocess(ctx, application.QuarantineReprocessInput{
		ID:      id,
		Adapter: adapter,
		// Actor is empty: the use case defaults to the I2 system
		// principal "operator" (application.defaultQuarantineActorID).
	})
	if err != nil {
		return demoErrorOutcome(err)
	}

	// Render the committed state (the authoritative row after the write,
	// timestamps and resolution links included).
	committed, out := readQuarantineRow(ctx, q, id)
	if !out.ok() {
		return out
	}
	view := quarantineRowView(committed, src.Type, src.Name)
	res := quarantineReprocessResult{
		quarantineView: view,
		Resolved:       result.Resolved,
		Records:        result.Records,
		Errors:         result.Errors,
	}

	if e.format == formatText {
		printQuarantineReprocess(e.stdout, res)
	}
	return e.ok(res)
}

// quarantineAdapters is the type-keyed registry of the reprocess command
// (ARCH-002 §1): the current implementation of every I2 source port,
// keyed by the source type a quarantine row names. The composition mirrors
// the worker registry (cmd/risksignal-worker/main.go) — one adapter
// instance per type serves every source row of that type; the transport
// and clock arguments are nil/defaults because reprocess only invokes the
// normalise half on stored raw record bytes (no fetch, no network). The
// I1b synthetic source is deliberately absent: its runs never isolate
// records into quarantine (the I1b run path reports the malformed
// reference case as a run error, README demo seed), so no quarantine row
// can name a synthetic source in practice.
func quarantineAdapters() map[string]application.SourcePort {
	return map[string]application.SourcePort{
		string(application.SourceTypeNVD):  nvd.New(nil),
		string(application.SourceTypeKEV):  kev.New(nil),
		string(application.SourceTypeEPSS): epss.New(nil, clock.RealClock{}),
	}
}

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
	if err := fs.Parse(flagTokensFirst(args)); err != nil {
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

// rowViewID formats the id of a stored row for messages.
func rowViewID(row gen.Quarantine) string { return demoUUID(row.ID) }

// quarantineSourceOf resolves the sources row of one stored quarantine
// row (its source attribution: type + name).
func (e *cmdEnv) quarantineSourceOf(ctx context.Context, q *gen.Queries, row gen.Quarantine) (gen.Source, outcome) {
	src, err := q.GetSourceByID(ctx, row.SourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return gen.Source{}, outcome{code: exitGeneric, class: classGeneric,
				message: fmt.Sprintf("quarantine %s references unknown source %s", demoUUID(row.ID), demoUUID(row.SourceID))}
		}
		return gen.Source{}, outcome{code: exitInfrastructure, class: classInfrastructure,
			message: err.Error()}
	}
	return src, outcome{}
}

// flagTokensFirst reorders the arguments of one quarantine subcommand so
// that every flag token — and, for a flag without an inline value, its
// following value token — precedes the positional arguments. Go's flag
// package stops parsing at the first non-flag argument, while the
// documented quarantine grammar places the positional id first
// (`quarantine ack <id> --note "…"`); the reorder lets the operator write
// flags before or after the id. The quarantine flag sets carry value flags
// only (--note, --status, --source, --limit), so a flag token always
// consumes the next token as its value when it carries no inline "=" — a
// boolean flag would need different handling and none of the quarantine
// subcommands has one.
func flagTokensFirst(args []string) []string {
	flags := make([]string, 0, len(args))
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			rest = append(rest, a)
			continue
		}
		flags = append(flags, a)
		if !strings.Contains(a, "=") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, rest...)
}

// quarantineViewOf resolves the source attribution of one stored row (its
// sources row: type + name) and renders the operator view.
func (e *cmdEnv) quarantineViewOf(ctx context.Context, q *gen.Queries, row gen.Quarantine) (quarantineView, outcome) {
	src, out := e.quarantineSourceOf(ctx, q, row)
	if !out.ok() {
		return quarantineView{}, out
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

// printQuarantineReprocess renders the reprocess outcome: the resolved
// verdict with the pass counts and the resolution link, or the audited
// still-failing verdict with the incremented attempts.
func printQuarantineReprocess(w io.Writer, res quarantineReprocessResult) {
	if res.Resolved {
		fmt.Fprintf(w, "quarantine %s reprocessed: resolved (records %d, errors %d), status %s at %s\n",
			res.ID, res.Records, res.Errors, res.Status, res.ResolvedAt)
		if res.ResolvedVulnerabilityID != "" {
			fmt.Fprintf(w, "  linked vulnerability %s\n", res.ResolvedVulnerabilityID)
		}
		if res.ResolvedEvidenceID != "" {
			fmt.Fprintf(w, "  linked evidence %s\n", res.ResolvedEvidenceID)
		}
	} else {
		fmt.Fprintf(w, "quarantine %s reprocessed: %d record(s) still fail to normalise (records %d) — attempts now %d, the row stays retryable (audited quarantine.reprocessed)\n",
			res.ID, res.Errors, res.Records, res.Attempts)
	}
}
