// `risksignal diagnose backup` and `risksignal diagnose restore-test` (and the
// `maintenance backup` alias): the I6 encrypted off-host backup and the
// repeatable restore test (ARCH-007 §4, NFR-011, AT-015, WP-6.09 / DEV-122).
//
// backup runs the daily logical `pg_dump -Fc` of the whole database, encrypts
// it with the runtime-injected `age` identity (backup.encryption_key_ref),
// writes it off-host (backup.dir) and prunes older artifacts down to
// backup.retain_days (≥14). It is deliberately not part of the application
// process: in production a containerised sidecar/cron runs the same command
// (see scripts/backup.sh and deploy/backup).
//
// restore-test decrypts the newest artifact, restores it into a throwaway
// empty database, runs the checksum-guarded migration runner (ADR-010,
// verifying the restored bookkeeping), asserts schema presence, object counts,
// sample-row hashes, open-signal integrity and the audit trail, and records a
// `backup.restored` audit event. The throwaway database is dropped afterwards
// (keep it with --keep). Both commands are strictly non-interactive.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/brunoxpera/risksignal/db/migrations"
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/migrate"
	"github.com/brunoxpera/risksignal/internal/platform/backup"
	"github.com/brunoxpera/risksignal/internal/platform/clock"
	"github.com/brunoxpera/risksignal/internal/platform/config"
)

const (
	// backupRunTimeout bounds one pg_dump + encrypt + prune cycle.
	backupRunTimeout = 5 * time.Minute
	// restoreTestTimeout bounds one decrypt + restore + migrate + assert cycle.
	restoreTestTimeout = 10 * time.Minute
)

// backupArtifactView is the machine-readable payload of a written backup.
type backupArtifactView struct {
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// restoreTestView is the machine-readable payload of a restore test.
type restoreTestView struct {
	BackupFile         string        `json:"backup_file"`
	Target             string        `json:"target"`
	Throwaway          bool          `json:"throwaway"`
	Kept               bool          `json:"kept"`
	MigrationsVerified int           `json:"migrations_verified"`
	MigrationsApplied  []int64       `json:"migrations_applied"`
	Integrity          backup.Report `json:"integrity"`
	Audited            bool          `json:"audited"`
}

// cmdBackup runs `risksignal diagnose backup [--pg-dump <cmd>]`: one encrypted,
// off-host logical backup. Failure classes: invalid arguments/configuration
// exit 2, an operational failure (dump/encrypt/write) exit 6.
func (e *cmdEnv) cmdBackup(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal diagnose backup\n"+
		"  run the encrypted (age) off-host logical pg_dump -Fc backup once\n"+
		"  (backup.dir, backup.encryption_key_ref, backup.retain_days)")
	pgDump := fs.String("pg-dump", "", "pg_dump executable (default: pg_dump on PATH)")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	settings, out := backupSettings(e, cfg)
	if !out.ok() {
		return out
	}
	settings.PGDump = *pgDump

	ctx, cancel := context.WithTimeout(context.Background(), backupRunTimeout)
	defer cancel()

	art, err := backup.Create(ctx, cfg.Database.URL, settings)
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}
	view := backupArtifactView{Path: art.Path, SizeBytes: art.SizeBytes, SHA256: art.SHA256, CreatedAt: art.CreatedAt}
	if e.format == formatText {
		fmt.Fprintf(e.stdout, "backup written: %s (%d bytes, sha256 %s)\n", art.Path, art.SizeBytes, art.SHA256)
	}
	return e.ok(view)
}

// cmdRestoreTest runs `risksignal diagnose restore-test [--backup <file>]
// [--target-database <dsn>] [--keep] [--reason <t>] [--as <subject>]`: decrypt
// the newest backup, restore it into a throwaway empty database, run the
// checksum-guarded migration runner, assert the restored data, record the
// `backup.restored` audit event and drop the throwaway database.
func (e *cmdEnv) cmdRestoreTest(args []string) outcome {
	fs := newFlagSet(e, "usage: risksignal diagnose restore-test [--backup <file>]\n"+
		"        [--target-database <dsn>] [--keep] [--reason <t>] [--as <subject>]\n"+
		"  --backup          the encrypted artifact to verify (default: newest under backup.dir)\n"+
		"  --target-database an existing empty database to restore into\n"+
		"                    (default: a throwaway database created and dropped)\n"+
		"  --keep            keep the throwaway database for inspection\n"+
		"  --reason          optional operator note recorded with the audit event\n"+
		"  --as              acting identity's issuer-qualified subject")
	backupFile := fs.String("backup", "", "the encrypted artifact to verify (default: newest under backup.dir)")
	targetDB := fs.String("target-database", "", "an existing empty database to restore into (default: a created throwaway database)")
	keep := fs.Bool("keep", false, "keep the throwaway database for inspection")
	reason := fs.String("reason", "", "optional operator note recorded with the audit event")
	as := fs.String("as", "", "acting identity's issuer-qualified subject")
	pgRestore := fs.String("pg-restore", "", "pg_restore executable (default: pg_restore on PATH)")
	if err := fs.Parse(args); err != nil {
		return flagParseOutcome(e, err)
	}
	if fs.NArg() > 0 {
		return e.fail(exitValidation, classValidation, "unexpected argument %q", fs.Arg(0))
	}

	cfg, out := loadConfig(e)
	if !out.ok() {
		return out
	}
	settings, out := backupSettings(e, cfg)
	if !out.ok() {
		return out
	}
	settings.PGRestore = *pgRestore

	ctx, cancel := context.WithTimeout(context.Background(), restoreTestTimeout)
	defer cancel()

	// Resolve the artifact: the explicit --backup file or the newest under
	// backup.dir.
	artifact := *backupFile
	if artifact == "" {
		latest, err := backup.Latest(cfg.Backup.Dir)
		if err != nil {
			return e.fail(exitGeneric, classGeneric, "%v", err)
		}
		artifact = latest
	}
	artifactName := filepath.Base(artifact)

	// Resolve the throwaway target: an operator-supplied empty database, or a
	// throwaway database this command creates and drops.
	targetURL := *targetDB
	throwaway := ""
	if targetURL == "" {
		name := backup.TempDatabaseName(clock.RealClock{}.Now())
		if err := backup.CreateDatabase(ctx, cfg.Database.URL, name); err != nil {
			return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
		}
		tmpURL, err := backup.DatabaseURLWithName(cfg.Database.URL, name)
		if err != nil {
			_ = backup.DropDatabase(ctx, cfg.Database.URL, name)
			return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
		}
		targetURL = tmpURL
		throwaway = name
		if !*keep {
			defer func() { _ = backup.DropDatabase(ctx, cfg.Database.URL, throwaway) }()
		}
	}

	// Decrypt into a private temp file.
	tmpDir, err := os.MkdirTemp("", "risksignal-restore-")
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "restore-test: create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	dumpPath := filepath.Join(tmpDir, "dump.pgcustom")
	if err := backup.Decrypt(artifact, dumpPath, settings.Identity); err != nil {
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}

	// Restore into the empty target.
	if err := backup.Restore(ctx, targetURL, dumpPath, settings); err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}

	// Run the checksum-guarded migration runner (ADR-010) against the restored
	// instance: it verifies the restored migration bookkeeping against the
	// embedded files (and applies any pending migration).
	runner, err := migrate.Open(ctx, targetURL, migrations.FS)
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}
	res, err := runner.Migrate(ctx, false)
	_ = runner.Close()
	if err != nil {
		var checksumErr *migrate.ChecksumError
		var missingErr *migrate.MigrationMissingError
		if errors.As(err, &checksumErr) || errors.As(err, &missingErr) {
			return e.fail(exitConflict, classConflict, "%v", err)
		}
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}

	// Assert schema, object counts, sample hashes, open signals and audit chain.
	report, err := backup.Verify(ctx, cfg.Database.URL, targetURL)
	if err != nil {
		return e.fail(exitInfrastructure, classInfrastructure, "%v", err)
	}
	if !report.Matched {
		return e.fail(exitConflict, classConflict,
			"restore test failed: restored instance does not reproduce the source (%v)", report.Mismatches)
	}

	// Record the audit event on the source database.
	actorID := signalSubject(cfg, *as)
	occurredAt := clock.RealClock{}.Now()
	if err := backup.RecordRestoreAudit(ctx, cfg.Database.URL, backup.RestoreAudit{
		BackupFile:    artifactName,
		RestoredTo:    targetDescriptor(throwaway),
		Tables:        report.Tables,
		Rows:          report.Rows,
		OpenSignals:   report.OpenSignals,
		AuditRows:     report.AuditRows,
		ChainVerified: report.ChainVerified,
		ActorID:       actorID,
		Reason:        *reason,
	}, occurredAt, "backup-restore-test:"+artifactName); err != nil {
		return e.fail(exitGeneric, classGeneric, "%v", err)
	}

	var applied []int64
	for _, a := range res.Applied {
		applied = append(applied, a.Version)
	}
	view := restoreTestView{
		BackupFile:         artifactName,
		Target:             targetDescriptor(throwaway),
		Throwaway:          throwaway != "",
		Kept:               *keep,
		MigrationsVerified: res.Verified,
		MigrationsApplied:  applied,
		Integrity:          report,
		Audited:            true,
	}
	if e.format == formatText {
		fmt.Fprintf(e.stdout, "restore test ok: %s -> %s\n", artifactName, view.Target)
		fmt.Fprintf(e.stdout, "  schema: %d table(s); rows: %d; open signals: %d; audit rows: %d; chain verified: %t\n",
			report.Tables, report.Rows, report.OpenSignals, report.AuditRows, report.ChainVerified)
		fmt.Fprintf(e.stdout, "  migrations: verified %d, applied %d\n", res.Verified, len(applied))
		fmt.Fprintln(e.stdout, "  audit event recorded: backup.restored")
	}
	return e.ok(view)
}

// backupSettings resolves the backup.Settings from the configuration, mapping
// a missing/invalid encryption-key reference onto a validation failure.
func backupSettings(e *cmdEnv, cfg *config.Config) (backup.Settings, outcome) {
	identity, err := backup.ResolveIdentity(cfg.Backup.EncryptionKeyRef)
	if err != nil {
		return backup.Settings{}, e.fail(exitValidation, classValidation, "%v", err)
	}
	return backup.Settings{
		Dir:        cfg.Backup.Dir,
		RetainDays: cfg.Backup.RetainDays,
		KeyRef:     cfg.Backup.EncryptionKeyRef,
		Identity:   identity,
	}, outcome{}
}

// targetDescriptor names the restore target without leaking credentials: the
// throwaway database name, or the operator-supplied database.
func targetDescriptor(throwaway string) string {
	if throwaway != "" {
		return "throwaway:" + throwaway
	}
	return "operator-provided"
}
