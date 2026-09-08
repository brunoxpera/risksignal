// maintenance subcommands (WP-1a.09): migrate is the real command wrapping
// the checksum-guarded migration runner of WP-1a.04; retention and recompute
// are recognised but not yet implemented and fail with exit code 1 instead
// of pretending to work. All maintenance commands are strictly
// non-interactive: they take complete parameters on the command line and
// never read a terminal.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/xpera/risksignal/db/migrations"
	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
)

// runMaintenance dispatches `risksignal maintenance ...`.
func runMaintenance(e *cmdEnv, args []string) int {
	if len(args) < 1 {
		return e.emit("maintenance", e.fail(exitValidation, classValidation,
			"missing subcommand (supported: migrate, retention, recompute)"))
	}
	command := "maintenance " + args[0]
	switch args[0] {
	case "migrate":
		return e.emit(command, e.cmdMigrate(args[1:]))
	case "retention", "recompute":
		return e.emit(command, e.cmdNotImplemented(args[1:]))
	default:
		return e.emit(command, e.fail(exitValidation, classValidation,
			"unknown subcommand (supported: migrate, retention, recompute)"))
	}
}

// cmdNotImplemented is the shared body of the maintenance stubs. The command
// is recognised but has no behaviour yet: any argument is rejected (nothing
// is accepted until the real implementation defines it) and the command
// fails with the generic exit code 1, never with a fake success.
func (e *cmdEnv) cmdNotImplemented(args []string) outcome {
	if len(args) > 0 {
		return e.fail(exitValidation, classValidation,
			"unexpected argument %q (not yet implemented — no options are accepted yet)", args[0])
	}
	return e.fail(exitGeneric, classGeneric,
		"not yet implemented (scheduled for a later work package)")
}

// migrateRunTimeout bounds one migration run; schema migrations of this
// scale finish far below it, the bound protects automation from hanging.
const migrateRunTimeout = 5 * time.Minute

// cmdMigrate runs `risksignal maintenance migrate [--dry-run]`: the
// checksum-guarded migration runner (WP-1a.04, ADR-010) against the
// database from database.url. Failure classes: an invalid configuration is
// exit 2, an unreachable database is exit 6 (infrastructure), an altered or
// missing applied migration is exit 5 (conflict, ADR-010) and any other
// runtime failure is exit 1 (generic).
func (e *cmdEnv) cmdMigrate(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal maintenance migrate [--dry-run]\n"+
		"  --dry-run  verify checksums and report pending migrations without\n"+
		"             changing the database")
	dryRun := fs.Bool("dry-run", false, "verify checksums and report pending migrations without changing the database")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return outcome{}
		}
		return e.fail(exitValidation, classValidation, "%v", err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}

	ctx, cancel := context.WithTimeout(context.Background(), migrateRunTimeout)
	defer cancel()

	runner, err := migrate.Open(ctx, cfg.Database.URL, migrations.FS)
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}
	defer runner.Close()

	res, err := runner.Migrate(ctx, *dryRun)
	if err != nil {
		var checksumErr *migrate.ChecksumError
		var missingErr *migrate.MigrationMissingError
		if errors.As(err, &checksumErr) || errors.As(err, &missingErr) {
			// The recorded migration history conflicts with the embedded
			// files (ADR-010): a state conflict, not an infrastructure or
			// generic failure.
			return e.fail(exitConflict, classConflict, "%v", err)
		}
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}

	if e.format == formatText {
		printMigrateResult(e.stdout, res)
	}
	return e.ok(migrateResultJSON(res))
}

// printMigrateResult renders the migration run outcome as human-readable
// text (WP-1a.04 format).
func printMigrateResult(w io.Writer, res *migrate.Result) {
	if res.DryRun {
		if len(res.Pending) == 0 && len(res.Recovered) == 0 {
			fmt.Fprintf(w, "dry run: verified checksums of %d applied migration(s); nothing to do\n", res.Verified)
			return
		}
		fmt.Fprintf(w, "dry run: verified checksums of %d applied migration(s); no changes were made\n", res.Verified)
		for _, p := range res.Pending {
			fmt.Fprintf(w, "  would apply   %s (version %d)\n", filepath.Base(p.Path), p.Version)
		}
		for _, r := range res.Recovered {
			fmt.Fprintf(w, "  would record  %s (version %d) in the checksum log\n", filepath.Base(r.Path), r.Version)
		}
		return
	}
	fmt.Fprintf(w, "verified checksums of %d applied migration(s)\n", res.Verified)
	for _, a := range res.Applied {
		fmt.Fprintf(w, "  applied   %s (version %d, %s)\n", filepath.Base(a.Path), a.Version, a.Duration.Round(time.Millisecond))
	}
	for _, r := range res.Recovered {
		fmt.Fprintf(w, "  recorded  %s (version %d) in the checksum log (was applied but unlogged)\n", filepath.Base(r.Path), r.Version)
	}
	if len(res.Applied) == 0 && len(res.Recovered) == 0 {
		fmt.Fprintln(w, "no pending migrations")
	}
}

// The JSON result payloads below mirror migrate.Result (internal/adapters/
// postgres/migrate) with fixed keys. Schema-stability: extend the payloads
// with optional keys, never rename or re-type existing ones.

// migrateResult is the machine-readable payload of a successful migrate run.
type migrateResult struct {
	DryRun    bool                 `json:"dry_run"`
	Verified  int                  `json:"verified"`
	Applied   []appliedMigration   `json:"applied"`
	Recovered []recoveredMigration `json:"recovered"`
	Pending   []pendingMigration   `json:"pending"`
}

// appliedMigration is one migration applied by a real run.
type appliedMigration struct {
	Version    int64  `json:"version"`
	Path       string `json:"path"`
	DurationMS int64  `json:"duration_ms"`
}

// recoveredMigration is one checksum-log row re-recorded from goose's
// bookkeeping (or, in a dry run, a row that would be re-recorded).
type recoveredMigration struct {
	Version int64  `json:"version"`
	Path    string `json:"path"`
}

// pendingMigration is one embedded migration that is not applied yet.
type pendingMigration struct {
	Version int64  `json:"version"`
	Path    string `json:"path"`
}

// migrateResultJSON converts a migrate.Result into its schema-stable JSON
// payload.
func migrateResultJSON(res *migrate.Result) migrateResult {
	out := migrateResult{
		DryRun:    res.DryRun,
		Verified:  res.Verified,
		Applied:   make([]appliedMigration, 0, len(res.Applied)),
		Recovered: make([]recoveredMigration, 0, len(res.Recovered)),
		Pending:   make([]pendingMigration, 0, len(res.Pending)),
	}
	for _, a := range res.Applied {
		out.Applied = append(out.Applied, appliedMigration{
			Version:    a.Version,
			Path:       a.Path,
			DurationMS: a.Duration.Milliseconds(),
		})
	}
	for _, r := range res.Recovered {
		out.Recovered = append(out.Recovered, recoveredMigration{Version: r.Version, Path: r.Path})
	}
	for _, p := range res.Pending {
		out.Pending = append(out.Pending, pendingMigration{Version: p.Version, Path: p.Path})
	}
	return out
}
