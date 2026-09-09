// inventory subcommands (WP-3.05 / DEV-059 + DEV-060, ARCH-003 §1.3,
// concept ch. 11.3): `inventory validate|preview|import` — the CSV
// inventory import pipeline of the CLI. The grammar is non-interactive:
// no command prompts, `import` never writes without an explicit
// confirmation flag (ch. 11.3: dry-run is mandatory for inventory
// imports; non-interactive commands take --yes or complete parameters).
//
//	validate <file>   pure parse: the positioned problem report of one
//	                  inventory CSV (header, row limits, enum validity,
//	                  identifier syntax, intra-file conflicts). Read-only
//	                  by construction — no database is opened.
//	preview <file>    the read-only diff against the current inventory:
//	                  which assets/components the file would create,
//	                  update or leave unchanged, the row/error counts and
//	                  the data-quality warnings (unknown
//	                  criticality/exposure). The only persistence contact
//	                  is the read-only InventoryRepo port.
//	import <file>     dry run by default: exactly the preview report,
//	                  nothing written. With --commit (or its ch. 11.3
//	                  alias --yes) the command commits the clean rows in
//	                  one transaction (postgres.WithTx): the additive
//	                  upserts on UQ (source, external_id) and UQ
//	                  (asset_id, natural_key), the inventory.import audit
//	                  event and — when the commit changed at least one row
//	                  — exactly one matching.rebuild outbox job whose
//	                  dedupe key is rule_version + inventory_snapshot
//	                  (ARCH-003 §5). Problem rows never write: the commit
//	                  applies exactly the clean rows the report shows,
//	                  next to the positioned problems that blocked the
//	                  rejected rows. A re-commit of identical content is a
//	                  no-op: no row rewritten, no rebuild enqueued.
//
// Composition: cmd/risksignal is the composition root of the command
// path — e.dbService wires the postgres repositories behind the
// application ports, including repo.InventoryRepo behind both the
// preview read port and the commit write path. The audit actor of a
// commit is the I2 system principal "operator" (application defaults it;
// user principals arrive with I5a, ch. 13.2).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/adapters/postgres/repo"
	"github.com/xpera/risksignal/internal/application"
)

// inventoryCommandTimeout bounds one database-backed inventory command
// (preview, import): a commit runs one transaction plus its current-state
// reads; the bound keeps automation from hanging on a stalled database
// (same convention as the quarantine commands).
const inventoryCommandTimeout = 5 * time.Minute

// runInventory dispatches `risksignal inventory ...`. Missing or unknown
// subcommands are validation failures (exit 2) reported before any
// configuration load or database open.
func runInventory(e *cmdEnv, args []string) int {
	if len(args) < 1 {
		return e.emit("inventory", e.fail(exitValidation, classValidation,
			"missing subcommand (supported: validate, preview, import)"))
	}
	command := "inventory " + args[0]
	switch args[0] {
	case "validate":
		return e.emit(command, e.cmdInventoryValidate(args[1:]))
	case "preview":
		return e.emit(command, e.cmdInventoryPreview(args[1:]))
	case "import":
		return e.emit(command, e.cmdInventoryImport(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation,
			"unknown subcommand (supported: validate, preview, import)"))
	}
}

// inventoryFlagsFirst reorders the arguments of one inventory subcommand
// so that every flag token precedes the positional file argument (Go's
// flag package stops parsing at the first non-flag argument, while the
// documented grammar places the file first: `inventory import <file>
// --commit`). The inventory flags are booleans (--commit, --yes) that may
// carry an inline value (--commit=true) and never consume the following
// token — unlike the value flags of the quarantine commands — so the
// reorder is a pure partition of the tokens.
func inventoryFlagsFirst(args []string) []string {
	flags := make([]string, 0, len(args))
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			continue
		}
		rest = append(rest, a)
	}
	return append(flags, rest...)
}

// inventoryProblemView is the fixed machine-readable shape of one
// positioned inventory failure (ARCH-003 §1.3: line, column, reason — a
// problem never aborts the file). Column is "" for problems that span a
// whole row or the header; Input is the offending cell verbatim ("" when
// no single cell is at fault).
type inventoryProblemView struct {
	Line   int    `json:"line"`
	Column string `json:"column"`
	Reason string `json:"reason"`
	Input  string `json:"input"`
}

// inventoryWarningView is the fixed shape of one data-quality warning
// (ARCH-003 §1.3 preview: unknown criticality/exposure).
type inventoryWarningView struct {
	Line   int    `json:"line"`
	Field  string `json:"field"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// inventoryTallyView is the fixed shape of the created/updated/unchanged
// counts of one preview or commit classification.
type inventoryTallyView struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
}

// inventoryAssetDiffView is the per-asset breakdown of a preview: the
// asset's diff status and the classification of every component it
// carries (line + status), so automation sees exactly which rows a commit
// would write.
type inventoryAssetDiffView struct {
	Source     string                       `json:"source"`
	ExternalID string                       `json:"external_id"`
	Status     string                       `json:"status"`
	Lines      []int                        `json:"lines"`
	Components []inventoryComponentDiffView `json:"components"`
}

// inventoryComponentDiffView is one per-component preview classification.
type inventoryComponentDiffView struct {
	Line   int    `json:"line"`
	Status string `json:"status"`
}

// inventoryValidateResult is the machine-readable payload of `inventory
// validate`: the row count and every positioned failure.
type inventoryValidateResult struct {
	Rows       int                    `json:"rows"`
	ErrorCount int                    `json:"error_count"`
	Errors     []inventoryProblemView `json:"errors"`
}

// inventoryPreviewResult is the machine-readable payload of `inventory
// preview`: the parse report, the data-quality warnings, the
// created/updated/unchanged tallies and the per-asset diff breakdown.
type inventoryPreviewResult struct {
	Rows       int                      `json:"rows"`
	ErrorCount int                      `json:"error_count"`
	Errors     []inventoryProblemView   `json:"errors"`
	Warnings   []inventoryWarningView   `json:"warnings"`
	Assets     inventoryTallyView       `json:"assets"`
	Components inventoryTallyView       `json:"components"`
	AssetDiffs []inventoryAssetDiffView `json:"asset_diffs"`
}

// inventoryImportResult is the machine-readable payload of `inventory
// import`. Without --commit/--yes the command is the mandatory dry run:
// DryRun is true, the report fields describe what a commit would change
// and nothing was written. With --commit/--yes the commit ran: DryRun is
// false and the report fields describe the committed classification (the
// authoritative, in-transaction diff); Changed reports whether any row
// was written, ImportID is the audit aggregate id of the commit and
// RuleVersion/InventorySnapshot describe the enqueued matching.rebuild
// job (empty when nothing changed — a re-commit of identical content
// enqueues no job).
type inventoryImportResult struct {
	Rows       int                    `json:"rows"`
	ErrorCount int                    `json:"error_count"`
	Errors     []inventoryProblemView `json:"errors"`
	Warnings   []inventoryWarningView `json:"warnings"`
	Assets     inventoryTallyView     `json:"assets"`
	Components inventoryTallyView     `json:"components"`

	DryRun            bool   `json:"dry_run"`
	Committed         bool   `json:"committed"`
	Changed           bool   `json:"changed"`
	ImportID          string `json:"import_id"`
	RuleVersion       string `json:"rule_version"`
	InventorySnapshot string `json:"inventory_snapshot"`
}

// cmdInventoryValidate parses one inventory CSV and reports every
// positioned failure (ARCH-003 §1.3 step 1). Read-only by construction:
// no configuration load, no database. A file with failures is a
// successful command (exit 0) whose report carries the count and the
// positioned problems — content failures never abort the file and the
// command itself never fails on content. Exit 2 covers invalid arguments
// (missing/unknown file, an oversized file —
// application.ErrInventoryTooLarge is a validation-class error).
func (e *cmdEnv) cmdInventoryValidate(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal inventory validate <file>\n"+
		"  parse one inventory CSV and report every positioned failure (line, column, reason);\n"+
		"  read-only, no database")
	if err := fs.Parse(inventoryFlagsFirst(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() != 1 {
		return e.fail(exitValidation, classValidation,
			"inventory validate takes exactly one argument: the inventory CSV file")
	}
	file := fs.Arg(0)
	data, out := readInventoryFile(file)
	if !out.ok() {
		return out
	}

	res, err := application.ValidateCSVInventory(strings.NewReader(string(data)))
	if err != nil {
		return demoErrorOutcome(err)
	}
	result := inventoryValidateResult{
		Rows:       res.Rows,
		ErrorCount: res.ErrorCount,
		Errors:     inventoryProblemsView(res.Errors),
	}
	if e.format == formatText {
		printInventoryValidate(e.stdout, file, result)
	}
	return e.ok(result)
}

// cmdInventoryPreview diffs one inventory CSV against the current
// inventory (ARCH-003 §1.3 step 2): read-only, the classification of
// every clean row — created / updated / unchanged per asset and component
// — plus the row/error counts and the data-quality warnings. The
// current-state read runs on the pool through the read-only
// application.InventoryRepo port.
func (e *cmdEnv) cmdInventoryPreview(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal inventory preview <file>\n"+
		"  diff one inventory CSV against the current inventory (created/updated/unchanged);\n"+
		"  read-only")
	if err := fs.Parse(inventoryFlagsFirst(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() != 1 {
		return e.fail(exitValidation, classValidation,
			"inventory preview takes exactly one argument: the inventory CSV file")
	}
	file := fs.Arg(0)
	data, out := readInventoryFile(file)
	if !out.ok() {
		return out
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), inventoryCommandTimeout)
	defer cancel()

	pool, _, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	res, err := application.PreviewInventoryCSV(ctx, strings.NewReader(string(data)), repo.NewInventoryRepo(gen.New(pool)))
	if err != nil {
		return demoErrorOutcome(err)
	}
	result := inventoryPreviewFrom(res)
	if e.format == formatText {
		printInventoryPreview(e.stdout, file, result)
	}
	return e.ok(result)
}

// cmdInventoryImport runs the mandatory dry run of one inventory import
// and — with --commit or its alias --yes — the commit (ARCH-003 §1.3 step
// 3). Without a commit flag the command is the preview report with
// DryRun true and nothing is written (ch. 11.3: dry-run is mandatory for
// inventory imports; the CLI never prompts). With a commit flag the clean
// rows commit in one transaction — the additive upserts, the
// inventory.import audit event and, when at least one row changed,
// exactly one matching.rebuild job (dedupe key rule_version +
// inventory_snapshot). The result report is the authoritative
// in-transaction classification; the positioned problems it carries name
// the rows a commit blocked — problem rows never write.
func (e *cmdEnv) cmdInventoryImport(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal inventory import <file> [--commit|--yes]\n"+
		"  dry run by default: preview one inventory CSV against the current inventory,\n"+
		"  nothing written. --commit (or its alias --yes) commits the clean rows in one\n"+
		"  transaction: additive upserts (UQ (source, external_id); UQ (asset_id,\n"+
		"  natural_key)), the inventory.import audit event and one matching.rebuild job\n"+
		"  when the commit changed inventory (ARCH-003 §5). Re-committing identical\n"+
		"  content is a no-op.")
	commit := fs.Bool("commit", false, "commit the clean rows of the file")
	yes := fs.Bool("yes", false, "alias of --commit (ch. 11.3: non-interactive confirmation)")
	if err := fs.Parse(inventoryFlagsFirst(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() != 1 {
		return e.fail(exitValidation, classValidation,
			"inventory import takes exactly one argument: the inventory CSV file")
	}
	file := fs.Arg(0)
	data, out := readInventoryFile(file)
	if !out.ok() {
		return out
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), inventoryCommandTimeout)
	defer cancel()

	pool, svc, out := e.dbService(ctx, cfg)
	if !out.ok() {
		return out
	}
	defer pool.Close()

	if !*commit && !*yes {
		// The mandatory dry run: read-only preview, nothing written.
		res, err := application.PreviewInventoryCSV(ctx, strings.NewReader(string(data)), repo.NewInventoryRepo(gen.New(pool)))
		if err != nil {
			return demoErrorOutcome(err)
		}
		result := inventoryImportResult{
			Rows:       res.Rows,
			ErrorCount: res.ErrorCount,
			Errors:     inventoryProblemsView(res.Errors),
			Warnings:   inventoryWarningsView(res.Warnings),
			Assets:     inventoryTallyView{Created: res.AssetsCreated, Updated: res.AssetsUpdated, Unchanged: res.AssetsUnchanged},
			Components: inventoryTallyView{Created: res.ComponentsCreated, Updated: res.ComponentsUpdated, Unchanged: res.ComponentsUnchanged},
			DryRun:     true,
		}
		if e.format == formatText {
			printInventoryImportDryRun(e.stdout, file, result)
		}
		return e.ok(result)
	}

	committed, err := svc.CommitInventory(ctx, application.CommitInventoryInput{File: data})
	if err != nil {
		return demoErrorOutcome(err)
	}
	result := inventoryImportResult{
		Rows:              committed.Rows,
		ErrorCount:        committed.ErrorCount,
		Errors:            inventoryProblemsView(committed.Errors),
		Warnings:          inventoryWarningsView(committed.Warnings),
		Assets:            inventoryTallyView{Created: committed.AssetsCreated, Updated: committed.AssetsUpdated, Unchanged: committed.AssetsUnchanged},
		Components:        inventoryTallyView{Created: committed.ComponentsCreated, Updated: committed.ComponentsUpdated, Unchanged: committed.ComponentsUnchanged},
		Committed:         true,
		Changed:           committed.Changed,
		ImportID:          committed.ImportID,
		RuleVersion:       committed.RuleVersion,
		InventorySnapshot: committed.InventorySnapshot,
	}
	if e.format == formatText {
		printInventoryImportCommitted(e.stdout, file, result)
	}
	return e.ok(result)
}

// readInventoryFile reads one inventory CSV bounded by the parser's
// whole-file resource limit (ARCH-003 §1.3 / ch. 12.3:
// application.InventoryMaxBytes — the same 16 MiB cap the parse enforces,
// applied here before the file is handed over). An unreadable file is a
// validation failure (the command argument names a file that cannot be
// read); an oversized file carries the parser's stable error message.
func readInventoryFile(path string) ([]byte, outcome) {
	f, err := os.Open(path)
	if err != nil {
		return nil, outcome{code: exitValidation, class: classValidation,
			message: fmt.Sprintf("cannot read inventory file %s: %v", path, err)}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, application.InventoryMaxBytes+1))
	if err != nil {
		return nil, outcome{code: exitValidation, class: classValidation,
			message: fmt.Sprintf("cannot read inventory file %s: %v", path, err)}
	}
	if len(data) > application.InventoryMaxBytes {
		return nil, outcome{code: exitValidation, class: classValidation,
			message: fmt.Sprintf("inventory file %s: %v", path, application.ErrInventoryTooLarge)}
	}
	return data, outcome{}
}

// inventoryProblemsView maps the positioned problems of one report onto
// their fixed machine-readable shape.
func inventoryProblemsView(problems []application.InventoryProblem) []inventoryProblemView {
	view := make([]inventoryProblemView, 0, len(problems))
	for _, p := range problems {
		view = append(view, inventoryProblemView{Line: p.Line, Column: p.Column, Reason: p.Reason, Input: p.Input})
	}
	return view
}

// inventoryWarningsView maps the data-quality warnings of one report.
func inventoryWarningsView(warnings []application.InventoryWarning) []inventoryWarningView {
	view := make([]inventoryWarningView, 0, len(warnings))
	for _, w := range warnings {
		view = append(view, inventoryWarningView{Line: w.Line, Field: w.Field, Value: w.Value, Reason: w.Reason})
	}
	return view
}

// inventoryPreviewFrom maps one preview result onto the machine-readable
// payload of the preview/import commands.
func inventoryPreviewFrom(res application.PreviewResult) inventoryPreviewResult {
	out := inventoryPreviewResult{
		Rows:       res.Rows,
		ErrorCount: res.ErrorCount,
		Errors:     inventoryProblemsView(res.Errors),
		Warnings:   inventoryWarningsView(res.Warnings),
		Assets:     inventoryTallyView{Created: res.AssetsCreated, Updated: res.AssetsUpdated, Unchanged: res.AssetsUnchanged},
		Components: inventoryTallyView{Created: res.ComponentsCreated, Updated: res.ComponentsUpdated, Unchanged: res.ComponentsUnchanged},
	}
	for _, d := range res.AssetDiffs {
		view := inventoryAssetDiffView{
			Source:     d.Source,
			ExternalID: d.ExternalID,
			Status:     string(d.Status),
			Lines:      append([]int(nil), d.Lines...),
		}
		for _, c := range d.Components {
			view.Components = append(view.Components, inventoryComponentDiffView{Line: c.Line, Status: string(c.Status)})
		}
		out.AssetDiffs = append(out.AssetDiffs, view)
	}
	return out
}

// ---------------------------------------------------------------------------
// text rendering

// printInventoryValidate renders the validate report.
func printInventoryValidate(w io.Writer, file string, res inventoryValidateResult) {
	fmt.Fprintf(w, "inventory validate %s: %d row(s), %d error(s)\n", file, res.Rows, res.ErrorCount)
	printInventoryProblemViews(w, res.Errors)
}

// printInventoryPreview renders the preview report: the summary counts,
// one line per asset diff and the errors/warnings.
func printInventoryPreview(w io.Writer, file string, res inventoryPreviewResult) {
	fmt.Fprintf(w, "inventory preview %s: %d row(s), %d error(s), %d warning(s)\n",
		file, res.Rows, res.ErrorCount, len(res.Warnings))
	fmt.Fprintf(w, "  assets: %d created, %d updated, %d unchanged\n", res.Assets.Created, res.Assets.Updated, res.Assets.Unchanged)
	fmt.Fprintf(w, "  components: %d created, %d updated, %d unchanged\n",
		res.Components.Created, res.Components.Updated, res.Components.Unchanged)
	for _, d := range res.AssetDiffs {
		fmt.Fprintf(w, "  (%s, %s): %s\n", d.Source, d.ExternalID, d.Status)
		for _, c := range d.Components {
			fmt.Fprintf(w, "    line %d: component %s\n", c.Line, c.Status)
		}
	}
	printInventoryWarningViews(w, res.Warnings)
	printInventoryProblemViews(w, res.Errors)
}

// printInventoryImportDryRun renders the dry run of `inventory import`:
// the summary and the explicit nothing-written marker.
func printInventoryImportDryRun(w io.Writer, file string, res inventoryImportResult) {
	fmt.Fprintf(w, "inventory import %s: dry run — no commit requested, nothing written (--commit or --yes commits)\n", file)
	fmt.Fprintf(w, "  %d row(s), %d error(s), %d warning(s)\n", res.Rows, res.ErrorCount, len(res.Warnings))
	fmt.Fprintf(w, "  assets: %d created, %d updated, %d unchanged\n", res.Assets.Created, res.Assets.Updated, res.Assets.Unchanged)
	fmt.Fprintf(w, "  components: %d created, %d updated, %d unchanged\n",
		res.Components.Created, res.Components.Updated, res.Components.Unchanged)
	printInventoryProblemViews(w, res.Errors)
	printInventoryWarningViews(w, res.Warnings)
}

// printInventoryImportCommitted renders a committed import: the
// authoritative in-transaction classification and the commit outcome
// (changed rows, the audit aggregate id, the enqueued rebuild job or the
// no-op verdict).
func printInventoryImportCommitted(w io.Writer, file string, res inventoryImportResult) {
	fmt.Fprintf(w, "inventory import %s: committed (import %s)\n", file, res.ImportID)
	fmt.Fprintf(w, "  %d row(s), %d error(s) blocked, %d warning(s)\n", res.Rows, res.ErrorCount, len(res.Warnings))
	fmt.Fprintf(w, "  assets: %d created, %d updated, %d unchanged\n", res.Assets.Created, res.Assets.Updated, res.Assets.Unchanged)
	fmt.Fprintf(w, "  components: %d created, %d updated, %d unchanged\n",
		res.Components.Created, res.Components.Updated, res.Components.Unchanged)
	if !res.Changed {
		fmt.Fprintln(w, "  nothing changed — re-commit of identical content is a no-op (no rebuild enqueued)")
	} else {
		fmt.Fprintf(w, "  matching.rebuild enqueued (rule_version %s, inventory_snapshot %s)\n", res.RuleVersion, res.InventorySnapshot)
	}
	printInventoryProblemViews(w, res.Errors)
	printInventoryWarningViews(w, res.Warnings)
}

// printInventoryProblemViews renders positioned problem views indented.
func printInventoryProblemViews(w io.Writer, problems []inventoryProblemView) {
	for _, p := range problems {
		fmt.Fprintf(w, "  line %d, column %s: %s (%q)\n", p.Line, p.Column, p.Reason, p.Input)
	}
}

// printInventoryWarningViews renders data-quality warning views indented.
func printInventoryWarningViews(out io.Writer, warnings []inventoryWarningView) {
	for _, w := range warnings {
		fmt.Fprintf(out, "  line %d, field %s: %s (value %q)\n", w.Line, w.Field, w.Reason, w.Value)
	}
}
