package application

// This file implements the I5b staged inventory-import orchestration of
// ARCH-006 §2.1 (WP-5b.03): StageInventoryImport (upload → validate +
// preview → persist a pending record), GetInventoryImport (read one stored
// record) and CommitStagedInventory (load the stored bytes → run the
// existing I3 CommitInventory → mark the record committed). None of the
// business logic is re-implemented here: the parse/validate/preview is the
// I3 PreviewInventoryCSV, the commit (parse, additive upsert, audit,
// matching.rebuild enqueue) is the I3 CommitInventory command — this file
// only orchestrates them and persists the staging record. All three use
// cases are gated on inventory.manage (deny-by-default); a denied call
// opens no transaction and writes nothing.
//
// The commit arm is idempotent (ARCH-006 §2.1: "Re-commit is a no-op"): a
// record already committed returns its stored result without re-running the
// I3 command, and the guarded commit-mark (`WHERE status = 'pending'`) makes
// a concurrent second commit a no-op too — its zero-row guard surfaces as
// marked = false (the adapter maps pgx.ErrNoRows onto the no-op). The four
// commit-outcome counters (assets_/components_ created/updated) are stamped
// from the I3 CommitInventoryResult atomically with the commit-mark, in the
// one guarded UPDATE.

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// InventoryImportStatus is the lifecycle of a staged inventory-import record
// (ARCH-006 §2.1): pending until committed (or, on an unrecoverable staging
// failure, failed). The vocabulary is fixed (also a DB CHECK).
type InventoryImportStatus string

// The staged-import lifecycle values.
const (
	InventoryImportPending   InventoryImportStatus = "pending"
	InventoryImportCommitted InventoryImportStatus = "committed"
	InventoryImportFailed    InventoryImportStatus = "failed"
)

// InventoryImportRecord is the stored staged-import row (ARCH-006 §2.1) as
// the application-level InventoryImportRepo persists and reads it. It is a
// read model, not a domain aggregate: the postgres adapter maps the generated
// inventory_imports row onto it (the application never imports the generated
// package). CreatedAt and CommittedAt are the staging and commit instants; a
// zero CommittedAt is NULL (still pending or failed). The four commit-outcome
// counters are 0 until the commit arm stamps them.
type InventoryImportRecord struct {
	ID     string
	Status InventoryImportStatus
	File   []byte

	Rows         int
	ErrorCount   int
	WarningCount int

	AssetsCreated     int
	AssetsUpdated     int
	ComponentsCreated int
	ComponentsUpdated int

	ActorID       string
	CorrelationID string
	CreatedAt     time.Time
	CommittedAt   time.Time // zero = NULL (pending or failed)
}

// InventoryImportCounts are the four commit-outcome counters of one commit
// (ARCH-006 §2.1): the assets/components the I3 CommitInventoryResult
// created and refreshed. They are stamped atomically with the commit-mark.
type InventoryImportCounts struct {
	AssetsCreated     int
	AssetsUpdated     int
	ComponentsCreated int
	ComponentsUpdated int
}

// InventoryImportRepo is the staging-port persistence of the I5b staged
// inventory import (ARCH-006 §2.1, WP-5b.02 schema / WP-5b.03 orchestration):
// the insert of a pending record, the by-id read, the guarded commit-mark and
// the operator list. The DEV-098 postgres adapter (over the
// inventory_imports queries) implements it; the writes run on the caller's
// transaction so the staging insert — and the commit-mark — are one
// transaction each. The port persists, it never re-implements the import
// business logic (that is the I3 command).
type InventoryImportRepo interface {
	// Insert stores one staged upload (status pending) on the caller's
	// transaction and returns the stored record with its database-assigned id.
	Insert(ctx context.Context, tx Tx, rec InventoryImportRecord) (InventoryImportRecord, error)

	// Get reads one staged record by its opaque import id. A missing id is a
	// not-found Error (the caller maps it to a 404).
	Get(ctx context.Context, id string) (InventoryImportRecord, error)

	// MarkCommitted flips a pending record to committed, stamps committed_at
	// from now and populates the four commit counters from counts — atomically,
	// in one guarded UPDATE. marked reports whether the guard matched: a
	// second commit of an already-committed (or failed) record matches zero
	// rows and reports marked = false with no error (the adapter maps
	// pgx.ErrNoRows onto that no-op, ARCH-006 §2.1).
	MarkCommitted(ctx context.Context, tx Tx, id string, counts InventoryImportCounts, now time.Time) (rec InventoryImportRecord, marked bool, err error)

	// List returns every staged record ordered by staging instant then id. An
	// empty table yields an empty slice, never an error.
	List(ctx context.Context) ([]InventoryImportRecord, error)
}

// InventoryImport is the application view of one staged import (ARCH-006
// §2.1) as the use cases return it: the record identity and lifecycle, the
// upload's row/error/warning counts, the created/updated/unchanged tallies
// and the positioned error/warning report. On the staging path the tallies
// are the preview diff (what a commit of the clean rows would change); on the
// commit path they are the CommitInventoryResult; on the plain read path the
// created/updated tallies are the stored commit outcome (0 while pending) and
// the unchanged tallies are unavailable (the staging table stores no unchanged
// column) and stay 0 — the positioned report is re-derived from the stored
// bytes.
type InventoryImport struct {
	ID     string
	Status InventoryImportStatus

	CreatedAt   time.Time
	CommittedAt time.Time // zero = NULL

	Rows         int
	ErrorCount   int
	WarningCount int

	AssetsCreated       int
	AssetsUpdated       int
	AssetsUnchanged     int
	ComponentsCreated   int
	ComponentsUpdated   int
	ComponentsUnchanged int

	Problems []InventoryProblem
	Warnings []InventoryWarning
}

// errImportsNotWired is the programming error of the staged-import use cases
// invoked without the InventoryImportRepo port.
var errImportsNotWired = errors.New("application: inventory-import repository is not wired")

// errInventoryReaderNotWired is the programming error of the staged-import
// staging path invoked without the current-state InventoryRepo the preview
// diffs against.
var errInventoryReaderNotWired = errors.New("application: inventory reader is not wired")

// StageInventoryImportInput is the staged-import upload (ARCH-006 §2.1, POST
// /inventory/imports): the CSV bytes (bounded by InventoryMaxBytes through the
// preview parser), the staging actor and an optional correlation id linking
// the record to the commit command's audit/outbox rows.
type StageInventoryImportInput struct {
	File          []byte
	Actor         Actor
	CorrelationID string
}

// StageInventoryImport validates and previews one inventory CSV against the
// current inventory and persists a pending staged record (ARCH-006 §2.1). It
// never writes to the inventory itself: the clean rows commit only through
// CommitStagedInventory. inventory.manage gates the call (deny-by-default);
// the parse/preview is the existing I3 PreviewInventoryCSV (a parse failure —
// an oversized or unreadable file — is reported before any transaction is
// opened, and a row-level failure is positioned in the report, never fatal).
func (s *Service) StageInventoryImport(ctx context.Context, in StageInventoryImportInput) (InventoryImport, error) {
	const op = "stage_inventory_import"

	// inventory.manage (Administrator-scope per the matrix): denied before the
	// parse and before any transaction, so a denied staging writes nothing
	// (ARCH-005 §5).
	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionInventoryManage, domain.ScopeAll, ""); err != nil {
		return InventoryImport{}, err
	}
	if s.inventoryReader == nil {
		return InventoryImport{}, InfraError(op, errInventoryReaderNotWired)
	}
	if s.imports == nil {
		return InventoryImport{}, InfraError(op, errImportsNotWired)
	}

	// Validate + preview in one parse pass (ARCH-003 §1.3 steps 1–2): the
	// positioned problems/warnings are the validate report, the created/
	// updated/unchanged tallies the preview diff. An oversized/unreadable file
	// is rejected here, before the transaction.
	preview, err := PreviewInventoryCSV(ctx, bytes.NewReader(in.File), s.inventoryReader)
	if err != nil {
		return InventoryImport{}, err
	}

	actor := inventoryActor(in.Actor)
	correlationID := correlationOrNew(in.CorrelationID)
	now := s.clock.Now()

	var stored InventoryImportRecord
	err = s.runTx(ctx, func(tx Tx) error {
		rec, err := s.imports.Insert(ctx, tx, InventoryImportRecord{
			Status:        InventoryImportPending,
			File:          in.File,
			Rows:          preview.Rows,
			ErrorCount:    preview.ErrorCount,
			WarningCount:  len(preview.Warnings),
			ActorID:       actor.ID,
			CorrelationID: correlationID,
			CreatedAt:     now,
		})
		if err != nil {
			return err
		}
		stored = rec
		return nil
	})
	if err != nil {
		return InventoryImport{}, err
	}

	return InventoryImport{
		ID:                  stored.ID,
		Status:              stored.Status,
		CreatedAt:           stored.CreatedAt,
		Rows:                preview.Rows,
		ErrorCount:          preview.ErrorCount,
		WarningCount:        len(preview.Warnings),
		AssetsCreated:       preview.AssetsCreated,
		AssetsUpdated:       preview.AssetsUpdated,
		AssetsUnchanged:     preview.AssetsUnchanged,
		ComponentsCreated:   preview.ComponentsCreated,
		ComponentsUpdated:   preview.ComponentsUpdated,
		ComponentsUnchanged: preview.ComponentsUnchanged,
		Problems:            preview.Errors,
		Warnings:            preview.Warnings,
	}, nil
}

// GetInventoryImportInput is the by-id staged-import read (ARCH-006 §2.1, GET
// /inventory/imports/{id}): the record id and the reading principal.
type GetInventoryImportInput struct {
	ID    string
	Actor Actor
}

// GetInventoryImport returns one stored staged-import record (ARCH-006 §2.1):
// its status, tallies and positioned error/warning report. inventory.manage
// gates the read; an unknown id is a not-found error (404). The positioned
// report is re-derived from the stored bytes (the staging table persists the
// uploaded CSV verbatim), so the read returns the same report the staging
// returned.
func (s *Service) GetInventoryImport(ctx context.Context, in GetInventoryImportInput) (InventoryImport, error) {
	const op = "get_inventory_import"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionInventoryManage, domain.ScopeAll, ""); err != nil {
		return InventoryImport{}, err
	}
	if in.ID == "" {
		return InventoryImport{}, Validationf(op, "import id must not be empty")
	}
	if s.imports == nil {
		return InventoryImport{}, InfraError(op, errImportsNotWired)
	}
	rec, err := s.imports.Get(ctx, in.ID)
	if err != nil {
		return InventoryImport{}, err
	}
	return s.inventoryImportView(op, rec)
}

// CommitStagedInventoryInput is the staged commit (ARCH-006 §2.1, POST
// /inventory/imports/{id}/commit): the record id and the committing principal.
type CommitStagedInventoryInput struct {
	ID    string
	Actor Actor
}

// CommitStagedInventory runs the existing I3 CommitInventory over a staged
// record's stored bytes and marks the record committed (ARCH-006 §2.1). The
// command is idempotent: an already-committed record returns its stored result
// without re-running the I3 command (and the guarded commit-mark makes a
// concurrent race a no-op too). The four commit-outcome counters are stamped
// from the CommitInventoryResult atomically with the commit-mark. A failed
// record is a conflict (409). inventory.manage gates the call; an unknown id
// is a not-found error (404).
func (s *Service) CommitStagedInventory(ctx context.Context, in CommitStagedInventoryInput) (InventoryImport, error) {
	const op = "commit_staged_inventory"

	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionInventoryManage, domain.ScopeAll, ""); err != nil {
		return InventoryImport{}, err
	}
	if in.ID == "" {
		return InventoryImport{}, Validationf(op, "import id must not be empty")
	}
	if s.imports == nil {
		return InventoryImport{}, InfraError(op, errImportsNotWired)
	}

	rec, err := s.imports.Get(ctx, in.ID)
	if err != nil {
		return InventoryImport{}, err
	}
	switch rec.Status {
	case InventoryImportCommitted:
		// Re-commit of an already-committed record is a no-op returning the
		// stored result (ARCH-006 §2.1); the I3 command never re-runs.
		return s.inventoryImportView(op, rec)
	case InventoryImportFailed:
		return InventoryImport{}, ConflictError(op, errors.New("staged import is failed; it cannot be committed"))
	}

	// The commit itself is the existing I3 command (its own transaction:
	// parse, additive upsert, audit, matching.rebuild enqueue); the staged
	// record's correlation id links the record to the command's audit/outbox.
	res, err := s.CommitInventory(ctx, CommitInventoryInput{
		File:          rec.File,
		Actor:         in.Actor,
		CorrelationID: rec.CorrelationID,
	})
	if err != nil {
		return InventoryImport{}, err
	}

	// Mark committed and stamp the four counters in one guarded UPDATE (the
	// mark is its own transaction; a concurrent second commit matches zero
	// rows and is a no-op).
	counts := InventoryImportCounts{
		AssetsCreated:     res.AssetsCreated,
		AssetsUpdated:     res.AssetsUpdated,
		ComponentsCreated: res.ComponentsCreated,
		ComponentsUpdated: res.ComponentsUpdated,
	}
	now := s.clock.Now()
	var marked InventoryImportRecord
	var ok bool
	err = s.runTx(ctx, func(tx Tx) error {
		row, didMark, err := s.imports.MarkCommitted(ctx, tx, in.ID, counts, now)
		if err != nil {
			return err
		}
		marked, ok = row, didMark
		return nil
	})
	if err != nil {
		return InventoryImport{}, err
	}
	if !ok {
		// The guard did not match (already committed concurrently): return the
		// stored result as the no-op.
		stored, err := s.imports.Get(ctx, in.ID)
		if err != nil {
			return InventoryImport{}, err
		}
		return s.inventoryImportView(op, stored)
	}

	view, err := s.inventoryImportView(op, marked)
	if err != nil {
		return InventoryImport{}, err
	}
	// The commit result's tallies and positioned report are authoritative
	// (they mirror the preview that staged the record).
	view.AssetsCreated = res.AssetsCreated
	view.AssetsUpdated = res.AssetsUpdated
	view.AssetsUnchanged = res.AssetsUnchanged
	view.ComponentsCreated = res.ComponentsCreated
	view.ComponentsUpdated = res.ComponentsUpdated
	view.ComponentsUnchanged = res.ComponentsUnchanged
	view.Problems = res.Errors
	view.Warnings = res.Warnings
	return view, nil
}

// inventoryImportView maps a stored record onto the application view (ARCH-006
// §2.1): the record identity/lifecycle, the stored row/error/warning counts
// and commit counters, and the positioned report re-derived from the stored
// bytes. The unchanged tallies are unavailable on this path (not persisted)
// and stay zero.
func (s *Service) inventoryImportView(op string, rec InventoryImportRecord) (InventoryImport, error) {
	view := InventoryImport{
		ID:                rec.ID,
		Status:            rec.Status,
		CreatedAt:         rec.CreatedAt,
		CommittedAt:       rec.CommittedAt,
		Rows:              rec.Rows,
		ErrorCount:        rec.ErrorCount,
		WarningCount:      rec.WarningCount,
		AssetsCreated:     rec.AssetsCreated,
		AssetsUpdated:     rec.AssetsUpdated,
		ComponentsCreated: rec.ComponentsCreated,
		ComponentsUpdated: rec.ComponentsUpdated,
	}
	// Re-derive the positioned report from the stored bytes (the staging table
	// keeps the uploaded CSV verbatim). A stored record always parses (it was
	// validated before staging); a failure is infrastructure, never user input.
	if len(rec.File) > 0 {
		file, err := ParseInventoryCSV(bytes.NewReader(rec.File))
		if err != nil {
			return InventoryImport{}, InfraError(op, err)
		}
		view.Problems = file.Problems
		view.Warnings = file.Warnings
	}
	return view, nil
}
