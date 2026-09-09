package application

// This file implements the validate use case of the WP-3.05 inventory
// import (ARCH-003 §1.3 step 1, DEV-059): a pure parse of one inventory
// CSV that reports every positioned failure plus the row and error
// counts. Validate never writes and never reads current state — a file
// can be validated without a database. The heavy lifting is the parser of
// inventory_import.go; this use case is the thin report over it that the
// CLI (DEV-060) and the API (I5b) will both call.
//
// Failure semantics follow ARCH-003 §1.3: every failure is positioned
// (line, column, reason) and a failing row never aborts the file —
// ValidateCSVInventory returns the complete report of one pass, and the
// caller decides what the file's error count means for the pipeline.

import "io"

// ValidateResult is the report of one inventory validate pass: the number
// of data rows read (after the header — readable records only, see
// InventoryFile.Rows) and every positioned failure. ErrorCount mirrors
// len(Errors) — kept as an explicit field so machine-readable output
// (CLI --output json, DEV-060) carries the count without deriving it.
type ValidateResult struct {
	Rows       int
	ErrorCount int
	Errors     []InventoryProblem
}

// ValidateCSVInventory parses one inventory CSV and reports every
// positioned failure (ARCH-003 §1.3 step 1). It is pure: no writes, no
// current-state reads. The returned error is non-nil only when parsing is
// impossible — an input at or above InventoryMaxBytes
// (ErrInventoryTooLarge) or an underlying read failure; content failures
// are all positioned in ValidateResult.Errors, never fatal.
func ValidateCSVInventory(r io.Reader) (ValidateResult, error) {
	file, err := ParseInventoryCSV(r)
	if err != nil {
		return ValidateResult{}, err
	}
	return ValidateResult{
		Rows:       file.Rows,
		ErrorCount: len(file.Problems),
		Errors:     file.Problems,
	}, nil
}
