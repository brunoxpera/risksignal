// Package migrations embeds the SQL migration files (ADR-010).
//
// The migrations are plain SQL under db/migrations, embedded into every
// binary via embed.FS so the schema ships inside the same immutable artefact
// as the application (implementation concept ch. 7.4, TR-002). goose reads
// them from this filesystem; the migration runner verifies their checksums
// before every run (ADR-010).
//
// Only the *.sql files are embedded; the package file itself never enters the
// filesystem passed to goose.
package migrations

import "embed"

// FS is the embedded migration filesystem. Its root contains the migration
// files directly (goose globs "*.sql" against the root).
//
//go:embed *.sql
var FS embed.FS
