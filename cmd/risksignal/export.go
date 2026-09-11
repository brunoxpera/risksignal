// `risksignal export ...` (concept ch. 11.3, ARCH-007 §1.1, WP-6.07 / DEV-119):
// the CLI form of the asynchronous export surface. It drives the same
// application use cases as the API endpoints
//
//	POST /api/v1/exports
//	GET  /api/v1/exports/{id}
//	GET  /api/v1/exports/{id}/download
//
// with the same in-command gate (exports.create, deny-by-default) and the same
// audit — the application layer is the gate of record, so no channel bypasses
// it (ARCH-005 §5, NFR-013 channel parity). The command vocabulary is 1:1 with
// the API:
//
//	risksignal export create   --format csv|json [filter flags] [--as <subject>]
//	risksignal export download --export <id> --out <file> [--as <subject>]
//
// The commands are strictly non-interactive (ch. 11.3): the format, the frozen
// filter and the export id are complete command-line arguments, never a
// terminal dialogue. The acting identity is selected with --as; it defaults to
// the configured auth.bypass_principal in the local namespace.

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// exportCommandTimeout bounds one export command: a create is one guarded
// transaction, a download one read plus one audit write.
const exportCommandTimeout = 30 * time.Second

// exportSubcommands lists the supported subcommands for the error message.
const exportSubcommands = "create, download"

// runExport dispatches `risksignal export <subcommand>`.
func runExport(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.emit("export", e.fail(exitValidation, classValidation, "missing subcommand (supported: %s)", exportSubcommands))
	}
	command := "export " + args[0]
	switch args[0] {
	case "create":
		return e.emit(command, e.cmdExportCreate(args[1:]))
	case "download":
		return e.emit(command, e.cmdExportDownload(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation, "unknown subcommand (supported: %s)", exportSubcommands))
	}
}

// cmdExportCreate runs `risksignal export create --format csv|json [filter
// flags] [--as <subject>]`: it freezes the filter context and the format and
// schedules the export.generate job (ARCH-007 §1.2).
func (e *cmdEnv) cmdExportCreate(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal export create --format csv|json [filter flags] [--as <subject>]\n"+
		"  --priority --status --asset-id --asset-type --product --cve\n"+
		"  --owner-id --source-id --created-from --created-to --sla-state --free-text\n"+
		"  freeze the ch. 10.4 signal filter context; --as names the acting identity.")
	format := fs.String("format", "", "serialisation format: csv or json (mandatory)")
	priority := fs.String("priority", "", "signal priority filter (P1..P4)")
	status := fs.String("status", "", "signal status filter (new, in_review, action_planned, resolved, accepted, not_affected)")
	assetID := fs.String("asset-id", "", "asset id filter")
	assetType := fs.String("asset-type", "", "asset type filter")
	product := fs.String("product", "", "product filter (substring)")
	cve := fs.String("cve", "", "vulnerability id filter")
	ownerID := fs.String("owner-id", "", "owner id filter")
	sourceID := fs.String("source-id", "", "source id filter")
	createdFrom := fs.String("created-from", "", "created_at lower bound (RFC 3339)")
	createdTo := fs.String("created-to", "", "created_at upper bound (RFC 3339)")
	slaState := fs.String("sla-state", "", "SLA state filter (breached, open, met, none)")
	freeText := fs.String("free-text", "", "free-text filter")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	f := export.Format(strings.TrimSpace(*format))
	if !f.Valid() {
		return e.fail(exitValidation, classValidation, "--format is mandatory and must be %q or %q", export.FormatCSV, export.FormatJSON)
	}
	filter, out := exportFilterFromFlags(exportFilterFlags{
		priority: *priority, status: *status, assetID: *assetID, assetType: *assetType,
		product: *product, cve: *cve, ownerID: *ownerID, sourceID: *sourceID,
		createdFrom: *createdFrom, createdTo: *createdTo, slaState: *slaState, freeText: *freeText,
	})
	if !out.ok() {
		return out
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), exportCommandTimeout)
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
	res, err := svc.CreateExport(ctx, application.CreateExportInput{Filter: filter, Format: f, Actor: actor})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	payload := exportRecordViewOf(res.Export)
	if e.format == formatText {
		fmt.Fprintf(e.stdout, "export %s: %s (%s)\n", payload.ID, payload.Status, payload.Format)
	}
	return e.ok(payload)
}

// cmdExportDownload runs `risksignal export download --export <id> --out
// <file> [--as <subject>]`: it streams the stored artifact to the file,
// time-limited the same way the API is (an expired export is a conflict, exit
// 5).
func (e *cmdEnv) cmdExportDownload(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal export download --export <id> --out <file> [--as <subject>]")
	exportID := fs.String("export", "", "export id to download (mandatory)")
	out := fs.String("out", "", "file to write the artifact to (mandatory)")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*exportID) == "" {
		return e.fail(exitValidation, classValidation, "--export is mandatory (the export id)")
	}
	if strings.TrimSpace(*out) == "" {
		return e.fail(exitValidation, classValidation, "--out is mandatory (the file to write the artifact to)")
	}

	cfg, outCfg := loadConfig(e)
	if !outCfg.ok() {
		return outCfg
	}
	ctx, cancel := context.WithTimeout(context.Background(), exportCommandTimeout)
	defer cancel()
	pool, svc, outCfg := e.dbService(ctx, cfg)
	if !outCfg.ok() {
		return outCfg
	}
	defer pool.Close()

	actor, outCfg := e.resolveSignalActor(ctx, svc, cfg, *as)
	if !outCfg.ok() {
		return outCfg
	}
	res, err := svc.DownloadExport(ctx, application.DownloadExportInput{ExportID: *exportID, Actor: actor})
	if err != nil {
		return applicationErrorOutcome(err)
	}
	defer func() { _ = res.Reader.Close() }()

	// The reader is closed on every path (defer above); a write failure is an
	// infrastructure failure, never a silent partial file.
	if err := writeArtifact(*out, res.Reader); err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "write %s: %v", *out, err)
	}
	payload := exportDownloadView{ExportID: *exportID, Path: *out, SizeBytes: res.SizeBytes, Checksum: res.Checksum}
	if e.format == formatText {
		fmt.Fprintf(e.stdout, "export %s: downloaded %d byte(s) to %s\n", payload.ExportID, payload.SizeBytes, payload.Path)
	}
	return e.ok(payload)
}

// writeArtifact streams r into the file at path (truncating an existing one).
func writeArtifact(path string, r io.Reader) error {
	f, err := os.Create(path) // #nosec G304 — path is the operator's explicit --out argument.
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// exportFilterFlags carries the raw filter flag values.
type exportFilterFlags struct {
	priority, status, assetID, assetType, product, cve, ownerID, sourceID string
	createdFrom, createdTo, slaState, freeText                            string
}

// exportFilterFromFlags builds the frozen §10.4 filter from the flags,
// validating the enum vocabularies the same way the API binding does (an
// out-of-vocabulary value is exit 2). Empty flags stay unset.
func exportFilterFromFlags(fl exportFilterFlags) (application.ExportFilter, outcome) {
	filter := application.ExportFilter{}
	if s := strings.TrimSpace(fl.priority); s != "" {
		p := domain.Priority(s)
		if !p.Valid() {
			return filter, outcome{code: exitValidation, class: classValidation, message: fmt.Sprintf("invalid --priority %q (P1, P2, P3, P4)", fl.priority)}
		}
		filter.Priority = &p
	}
	if s := strings.TrimSpace(fl.status); s != "" {
		st := domain.SignalStatus(s)
		if !st.Valid() {
			return filter, outcome{code: exitValidation, class: classValidation, message: fmt.Sprintf("invalid --status %q", fl.status)}
		}
		filter.Status = &st
	}
	if s := strings.TrimSpace(fl.assetType); s != "" {
		at := domain.AssetType(s)
		if !at.Valid() {
			return filter, outcome{code: exitValidation, class: classValidation, message: fmt.Sprintf("invalid --asset-type %q", fl.assetType)}
		}
		filter.AssetType = &at
	}
	if s := strings.TrimSpace(fl.slaState); s != "" {
		sl := application.ExportSLAState(s)
		if !sl.Valid() {
			return filter, outcome{code: exitValidation, class: classValidation, message: fmt.Sprintf("invalid --sla-state %q (breached, open, met, none)", fl.slaState)}
		}
		filter.SLAState = &sl
	}
	filter.AssetID = strings.TrimSpace(fl.assetID)
	filter.Product = strings.TrimSpace(fl.product)
	filter.Cve = strings.TrimSpace(fl.cve)
	filter.SourceID = strings.TrimSpace(fl.sourceID)
	filter.FreeText = strings.TrimSpace(fl.freeText)
	if s := strings.TrimSpace(fl.ownerID); s != "" {
		filter.OwnerID = &s
	}
	from, out := parseRFC3339Flag("--created-from", fl.createdFrom)
	if !out.ok() {
		return filter, out
	}
	filter.CreatedFrom = from
	to, out := parseRFC3339Flag("--created-to", fl.createdTo)
	if !out.ok() {
		return filter, out
	}
	filter.CreatedTo = to
	return filter, outcome{}
}

// parseRFC3339Flag parses an optional RFC 3339 timestamp flag; empty stays nil.
func parseRFC3339Flag(name, value string) (*time.Time, outcome) {
	s := strings.TrimSpace(value)
	if s == "" {
		return nil, outcome{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, outcome{code: exitValidation, class: classValidation, message: fmt.Sprintf("%s: must be an RFC 3339 timestamp such as 2026-01-02T15:04:05Z", name)}
	}
	return &t, outcome{}
}

// exportRecordView is the machine-readable export record (mirrors the API
// ExportRecord; the generation stamps are null until completed).
type exportRecordView struct {
	ID            string                   `json:"id"`
	Status        string                   `json:"status"`
	Format        string                   `json:"format"`
	Filter        application.ExportFilter `json:"filter"`
	CreatedAt     time.Time                `json:"created_at"`
	RowCount      *int                     `json:"row_count"`
	SizeBytes     *int64                   `json:"size_bytes"`
	Checksum      *string                  `json:"checksum"`
	SchemaVersion *string                  `json:"schema_version"`
	RuleVersion   *string                  `json:"rule_version"`
	ExpiresAt     *time.Time               `json:"expires_at"`
}

// exportRecordViewOf maps a stored export onto the wire view.
func exportRecordViewOf(x application.Export) exportRecordView {
	view := exportRecordView{
		ID:        x.ID,
		Status:    string(x.Status),
		Format:    string(x.Format),
		Filter:    x.Filter,
		CreatedAt: x.CreatedAt,
	}
	if x.Status == application.ExportStatusCompleted {
		rowCount := x.RowCount
		sizeBytes := x.SizeBytes
		checksum := x.Checksum
		schemaVersion := x.SchemaVersion
		ruleVersion := x.RuleVersion
		view.RowCount = &rowCount
		view.SizeBytes = &sizeBytes
		view.Checksum = &checksum
		view.SchemaVersion = &schemaVersion
		view.RuleVersion = &ruleVersion
		if !x.ExpiresAt.IsZero() {
			expiresAt := x.ExpiresAt
			view.ExpiresAt = &expiresAt
		}
	}
	return view
}

// exportDownloadView is the machine-readable download result.
type exportDownloadView struct {
	ExportID  string `json:"export_id"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	Checksum  string `json:"checksum,omitempty"`
}
