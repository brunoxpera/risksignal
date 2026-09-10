package application

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/brunoxpera/risksignal/internal/application/export"
	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// This file owns the CreateExport command (ARCH-007 §1.2, WP-6.04 /
// DEV-115): the one domain command behind POST /exports. It freezes the
// §10.4 filter context and the creation instant, inserts a 'pending' export
// row and enqueues exactly one export.generate outbox job — the row and the
// job commit or roll back together (one command, one transaction, ch. 5.1).
// The materialisation itself is the export.generate worker job (WP-6.06);
// this command only schedules it.

// Export command vocabulary (ARCH-007 §1.2/§14.1).
const (
	// EventTypeExportGenerate is the outbox type discriminator of the
	// export.generate job (ARCH-007 §1.2/§14.1): the worker handler loads the
	// export row, streams the filtered signal set through the
	// SignalExportSource port, materialises the artifact and stamps the row.
	EventTypeExportGenerate = "export.generate"
	// AuditAggregateExport is the aggregate type of export audit rows
	// (ARCH-007 §1.2/§10.4): the download act is audited against it.
	AuditAggregateExport = "export"
)

// exportGenerateDedupePrefix namespaces the outbox dedupe key of the
// export.generate job (ARCH-007 §14.1: idempotency key export_id).
const exportGenerateDedupePrefix = "export.generate:"

// CreateExportInput is the CreateExport command. Filter is the frozen §10.4
// signal filter context; Format is csv|json. Actor is the authenticated
// principal — exports.create is gated per the matrix and an
// `assigned`/`own` grant freezes the filter to the principal's own signals.
type CreateExportInput struct {
	Filter        ExportFilter
	Format        export.Format
	Actor         Actor
	CorrelationID string
}

// CreateExportResult reports the created export: its id and initial status,
// the frozen creation instant and the command's correlation id (which links
// the export.generate outbox row to the command).
type CreateExportResult struct {
	ExportID      string
	Status        ExportStatus
	CreatedAt     time.Time
	CorrelationID string
}

// ExportGeneratePayload is the outbox payload of an export.generate job
// (ARCH-007 §1.2): the house envelope plus the export id the job loads. It
// carries identities and the frozen instant only — the filter lives in the
// exports row, never duplicated into the job payload (the row is the single
// source of the frozen filter).
type ExportGeneratePayload struct {
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	ExportID      string    `json:"export_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	CorrelationID string    `json:"correlation_id"`
}

// CreateExport creates one asynchronous export (ARCH-007 §1.2): it
// authorises exports.create (deny-by-default, before any transaction),
// validates the bounded frozen filter (reusing the ListSignals filter
// validation), freezes the filter — injecting the creator's owner scope for
// an `assigned`/`own` grant — and, inside one transaction, inserts the
// 'pending' export row and enqueues the export.generate outbox job keyed on
// the export id. A failing outbox append rolls the row back with it, so no
// export can exist without its job (the ARCH-001 §5 seam).
func (s *Service) CreateExport(ctx context.Context, in CreateExportInput) (CreateExportResult, error) {
	const op = "create_export"

	actor, err := signalActor(op, in.Actor)
	if err != nil {
		return CreateExportResult{}, err
	}
	if s.exports == nil {
		return CreateExportResult{}, InfraError(op, errors.New("export repository is not wired"))
	}

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return CreateExportResult{}, err
	}
	// exports.create at the assigned scope: an all-scope role passes
	// unconditionally, an assigned-scope role (Systemverantwortliche) passes
	// for its own export (the object owner is the creator itself). Any other
	// principal is denied before a transaction is opened and nothing is
	// written (ARCH-005 §5).
	if err := s.authorizeObject(op, principal, domain.PermissionExportsCreate, domain.ScopeAssigned, principal.InternalID); err != nil {
		return CreateExportResult{}, err
	}

	if !in.Format.Valid() {
		return CreateExportResult{}, Validationf(op, "invalid format %q (want %q or %q)", in.Format, export.FormatCSV, export.FormatJSON)
	}
	if err := in.Filter.Validate(op); err != nil {
		return CreateExportResult{}, err
	}

	// Object scope: an `assigned`/`own` exports.create grant freezes the
	// filter to the principal's own signals (owner_id = principal.id), the
	// query-path half of the object-scope rule (ARCH-005 §5) — the frozen
	// filter can never range beyond the creator's assignment, whatever the
	// request asked for.
	filter := in.Filter
	scope := principal.GrantedScope(domain.PermissionExportsCreate)
	if principal.InternalID != "" && (scope == domain.ScopeAssigned || scope == domain.ScopeOwn) {
		owner := principal.InternalID
		filter.OwnerID = &owner
	}

	now := s.clock.Now()
	correlationID := correlationOrNew(in.CorrelationID)

	var stored Export
	err = s.runTx(ctx, func(tx Tx) error {
		row, err := s.exports.Insert(ctx, tx, ExportRecord{
			Filter:    filter,
			Format:    in.Format,
			CreatedBy: actor.ID,
			CreatedAt: now,
		})
		if err != nil {
			return err
		}
		stored = row

		payload, err := json.Marshal(ExportGeneratePayload{
			EventID:       uuid.New(),
			Type:          EventTypeExportGenerate,
			ExportID:      row.ID,
			OccurredAt:    now,
			CorrelationID: correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		// The job append is the fault seam: a failure rolls the export row
		// back with it (ARCH-001 §5). The dedupe key is the export id, so a
		// retried command can never double-enqueue (ADR-012).
		return s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypeExportGenerate,
			Payload:     payload,
			DedupeKey:   exportGenerateDedupeKey(row.ID),
			AvailableAt: now,
			CreatedAt:   now,
		})
	})
	if err != nil {
		return CreateExportResult{}, err
	}
	return CreateExportResult{
		ExportID:      stored.ID,
		Status:        stored.Status,
		CreatedAt:     stored.CreatedAt,
		CorrelationID: correlationID,
	}, nil
}

// exportGenerateDedupeKey is the outbox dedupe key of one export.generate
// job (ARCH-007 §14.1: idempotency key export_id). It is unique for the
// row's whole lifetime, so the outbox UQ makes a re-enqueue of the same
// export a no-op.
func exportGenerateDedupeKey(exportID string) string {
	return exportGenerateDedupePrefix + exportID
}

// exportSnapshot is the minimised audit snapshot of an export act (ch. 13.5):
// identity, format and the generation stamps — counts and hashes only, never
// the frozen filter's free text or any signal content.
type exportSnapshot struct {
	ExportID      string `json:"export_id"`
	Status        string `json:"status"`
	Format        string `json:"format"`
	RowCount      int    `json:"row_count,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`
	Checksum      string `json:"checksum,omitempty"`
	SchemaVersion string `json:"schema_version,omitempty"`
	RuleVersion   string `json:"rule_version,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// newExportSnapshot projects one export row onto its minimised audit snapshot.
func newExportSnapshot(e Export) exportSnapshot {
	snap := exportSnapshot{
		ExportID:      e.ID,
		Status:        string(e.Status),
		Format:        string(e.Format),
		RowCount:      e.RowCount,
		SizeBytes:     e.SizeBytes,
		Checksum:      e.Checksum,
		SchemaVersion: e.SchemaVersion,
		RuleVersion:   e.RuleVersion,
	}
	if !e.ExpiresAt.IsZero() {
		snap.ExpiresAt = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return snap
}
