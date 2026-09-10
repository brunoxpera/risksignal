package application

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file owns the GenerateExport use case (ARCH-007 §1.2, WP-6.06 /
// DEV-118): the materialisation the `export.generate` worker job drives. It is
// a read-model materialisation (a read, a file write and one status UPDATE),
// not a state-changing domain command: it loads the export row, streams the
// frozen filter through the SignalExportSource read, materialises CSV/JSON
// through the neutralising writer (§1.3), writes the artifact into the spool,
// hashes it and stamps the generation columns (status/counts/size/checksum,
// schema_version, rule_version = MAX(priority_rules.version), expires_at).
//
// It is idempotent on the export id (a completed/expired row is skipped) and
// crash-safe (a retry after a crash or a failed generation regenerates the
// artifact and re-stamps the row; the spool write is atomic and the
// MarkCompleted guard keeps the stamp set-once from 'pending'/'failed').
// A generation failure records status='failed' + last_error, visible like any
// dead-letter/source-runs error; a permanent error dead-letters the job, an
// infrastructure error is retried by the relay after the lease expires.

// Export materialisation defaults (ARCH-007 §1.2/§2.4 config, injected via
// ServiceDeps).
const (
	// DefaultExportTTL is the export artifact lifetime (export.ttl): the
	// artifact self-expires and the sweep deletes it after this window.
	DefaultExportTTL = 7 * 24 * time.Hour
	// DefaultExportMaxRows bounds a single export (export.max_rows, the
	// strict input limit of §12.3): a filter matching more rows is rejected,
	// never silently truncated.
	DefaultExportMaxRows = 100000
)

// GenerateExportInput is the materialisation command the worker job invokes.
// Actor is the trusted system principal of the worker; CorrelationID links the
// generation to the creating command's chain (empty generates one).
type GenerateExportInput struct {
	ExportID      string
	CorrelationID string
}

// GenerateExportResult reports the materialisation: the export identity, its
// terminal status, the generation stamps and Skipped (true when the row was
// already completed/expired and nothing was regenerated — the idempotent
// no-op).
type GenerateExportResult struct {
	ExportID      string
	Status        ExportStatus
	Skipped       bool
	RowCount      int
	SizeBytes     int64
	Checksum      string
	SchemaVersion string
	RuleVersion   string
	ExpiresAt     time.Time
}

// GenerateExport materialises one export (ARCH-007 §1.2). The flow:
//
//  1. Load the export row; a completed/expired row is an idempotent no-op
//     (the job was redelivered after a successful materialisation).
//  2. Stream the frozen filter through SignalExportSource (the §10.4 standard
//     sort), bounded by export.max_rows.
//  3. Materialise the artifact through the neutralising CSV/JSON writer and
//     write it into the spool (atomic write + SHA-256).
//  4. Stamp the row 'completed' (counts, size, checksum, schema/rule version,
//     expiry) in one transaction.
//
// A generation failure records status='failed' + last_error and returns the
// error (classified for the relay); a redelivered attempt regenerates.
func (s *Service) GenerateExport(ctx context.Context, in GenerateExportInput) (GenerateExportResult, error) {
	const op = "generate_export"

	if s.exports == nil {
		return GenerateExportResult{}, InfraError(op, errors.New("export repository is not wired"))
	}
	if in.ExportID == "" {
		return GenerateExportResult{}, Validationf(op, "export id must not be empty")
	}

	row, err := s.exports.GetByID(ctx, in.ExportID)
	if err != nil {
		return GenerateExportResult{}, err
	}
	// Idempotent: a completed (or swept) export is already materialised; a
	// redelivered job is a no-op, never a second generation.
	if row.Status == ExportStatusCompleted || row.Status == ExportStatusExpired {
		return GenerateExportResult{
			ExportID:      row.ID,
			Status:        row.Status,
			Skipped:       true,
			RowCount:      row.RowCount,
			SizeBytes:     row.SizeBytes,
			Checksum:      row.Checksum,
			SchemaVersion: row.SchemaVersion,
			RuleVersion:   row.RuleVersion,
			ExpiresAt:     row.ExpiresAt,
		}, nil
	}
	if s.signalExport == nil {
		return GenerateExportResult{}, InfraError(op, errors.New("signal export source is not wired"))
	}
	if s.exportStore == nil {
		return GenerateExportResult{}, InfraError(op, errors.New("export artifact store is not wired"))
	}

	now := s.clock.Now()
	ruleVersion, err := s.exportRuleVersion(ctx, op)
	if err != nil {
		s.recordExportFailure(ctx, op, row.ID, err)
		return GenerateExportResult{}, err
	}

	rows, err := s.signalExport.Scan(ctx, row.Filter, now)
	if err != nil {
		s.recordExportFailure(ctx, op, row.ID, err)
		return GenerateExportResult{}, err
	}
	if s.exportMaxRows > 0 && len(rows) > s.exportMaxRows {
		err := Validationf(op, "export matches %d rows, exceeding export.max_rows %d", len(rows), s.exportMaxRows)
		s.recordExportFailure(ctx, op, row.ID, err)
		return GenerateExportResult{}, err
	}

	var buf bytes.Buffer
	if err := export.Write(&buf, row.Format, export.Document{
		RuleVersion: ruleVersion,
		CreatedAt:   row.CreatedAt,
		Rows:        rows,
	}); err != nil {
		werr := InfraError(op, err)
		s.recordExportFailure(ctx, op, row.ID, werr)
		return GenerateExportResult{}, werr
	}

	artifact, err := s.exportStore.Write(ctx, export.ArtifactKey(row.ID, row.Format), bytes.NewReader(buf.Bytes()))
	if err != nil {
		s.recordExportFailure(ctx, op, row.ID, err)
		return GenerateExportResult{}, err
	}

	done := ExportCompletion{
		ID:            row.ID,
		StoragePath:   artifact.Path,
		RowCount:      len(rows),
		SizeBytes:     artifact.SizeBytes,
		Checksum:      artifact.Checksum,
		SchemaVersion: export.SchemaVersion,
		RuleVersion:   ruleVersion,
		ExpiresAt:     now.Add(s.exportTTL),
	}
	var stamped Export
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.exports.MarkCompleted(ctx, tx, done)
		if err != nil {
			return err
		}
		stamped = row
		return nil
	})
	if err != nil {
		return GenerateExportResult{}, err
	}
	return GenerateExportResult{
		ExportID:      stamped.ID,
		Status:        stamped.Status,
		RowCount:      stamped.RowCount,
		SizeBytes:     stamped.SizeBytes,
		Checksum:      stamped.Checksum,
		SchemaVersion: stamped.SchemaVersion,
		RuleVersion:   stamped.RuleVersion,
		ExpiresAt:     stamped.ExpiresAt,
	}, nil
}

// exportRuleVersion resolves the rule version stamped at generation time
// (ARCH-007 §1.2): MAX(priority_rules.version) rendered through
// domain.PriorityRuleVersion. With no ruleset published (or no priority-rules
// port wired) it falls back to the legacy I1b tag, the same "no ruleset"
// sentinel the create path uses.
func (s *Service) exportRuleVersion(ctx context.Context, op string) (string, error) {
	if s.priorityRules == nil {
		return domain.PriorityRuleVersionI1b, nil
	}
	v, err := s.priorityRules.EffectiveVersion(ctx)
	if err != nil {
		return "", err
	}
	if v < 1 {
		return domain.PriorityRuleVersionI1b, nil
	}
	rv, err := domain.PriorityRuleVersion(v)
	if err != nil {
		return "", InfraError(op, err)
	}
	return rv, nil
}

// recordExportFailure best-effort records a failed generation
// (status='failed' + last_error, ARCH-007 §1.2) so the failure is visible
// like any dead-letter/source-runs error. The original generation error is
// the one returned to the caller; a failure of the failure-recording is
// swallowed (the row stays 'pending'/'failed' and a retry re-stamps it).
func (s *Service) recordExportFailure(ctx context.Context, op, exportID string, cause error) {
	if s.exports == nil {
		return
	}
	_ = s.runTx(ctx, func(tx Tx) error {
		_, err := s.exports.MarkFailed(ctx, tx, exportID, cause.Error())
		return err
	})
}
