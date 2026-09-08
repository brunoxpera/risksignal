// Package migrate runs the SQL schema migrations with checksum protection
// (ADR-010, WP-1a.04).
//
// goose is embedded as a library: the migration files under db/migrations are
// embedded into the binary via embed.FS and applied through goose's provider
// API (goose.Provider), which serializes concurrent runs with a PostgreSQL
// advisory lock. The checksum log (table schema_migration_log, created by the
// first migration) is our own layer on top: before every run the hashes of
// the already-applied migrations are verified against the embedded files —
// any divergence aborts before goose executes anything — and after applying,
// every migration is recorded with version, file hash, timestamp and
// duration. Migrations that goose applied but that are missing from the log
// (e.g. after a crash between goose's commit and the log insert) are
// re-recorded from goose's bookkeeping on the next run.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"sort"
	"time"

	// pgx registers the "pgx" database/sql driver used to open the
	// connection (ADR-009: pgx is the PostgreSQL driver of choice).
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

// Table names. schema_migration_log is our checksum log (ADR-010) and is
// created by the first migration; goose_db_version is goose's own
// bookkeeping table, created by goose itself.
const (
	checksumLogTable = "schema_migration_log"
	gooseTable       = "goose_db_version"
)

// Runner migrates a PostgreSQL schema with goose and enforces the checksum
// log. Create it with Open; a Runner is not safe for concurrent Migrate
// calls — use one Runner (or process) per run, goose serializes the actual
// work across processes with its advisory lock.
type Runner struct {
	db     *sql.DB
	fsys   fs.FS
	locker lock.SessionLocker
}

// Open connects to the PostgreSQL database at databaseURL (pgx over
// database/sql) and prepares a checksum-guarded runner over the migration
// files in fsys. It pings the database so configuration errors surface
// immediately.
func Open(ctx context.Context, databaseURL string, fsys fs.FS) (*Runner, error) {
	if databaseURL == "" {
		return nil, errors.New("migrate: database url is empty")
	}
	if fsys == nil {
		return nil, errors.New("migrate: migrations filesystem is nil")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("migrate: open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: connect to database: %w", err)
	}
	// The provider acquires a PostgreSQL session advisory lock while
	// migrating (goose lock package, crc64 of "goose"); concurrent runners —
	// other processes or instances — block until the lock is released, so
	// only one instance migrates at a time.
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: create advisory lock: %w", err)
	}
	return &Runner{db: db, fsys: fsys, locker: locker}, nil
}

// Close closes the database connection.
func (r *Runner) Close() error {
	return r.db.Close()
}

// AppliedMigration is a migration applied by this run.
type AppliedMigration struct {
	Version  int64
	Path     string
	Duration time.Duration
}

// RecoveredMigration is an applied migration whose checksum-log row was
// missing and had to be re-recorded from goose's bookkeeping. In a dry run it
// is a row that would be re-recorded.
type RecoveredMigration struct {
	Version int64
	Path    string
}

// PendingMigration is an embedded migration that is not yet applied.
type PendingMigration struct {
	Version int64
	Path    string
}

// Result describes one Migrate run.
type Result struct {
	// DryRun reports whether the run was read-only.
	DryRun bool
	// Verified counts the already-applied migrations whose stored checksum
	// matched the embedded file.
	Verified int
	// Applied lists the migrations applied by this run (real runs only).
	Applied []AppliedMigration
	// Recovered lists re-recorded checksum-log rows. In a dry run these rows
	// would be recorded but nothing was written.
	Recovered []RecoveredMigration
	// Pending lists the embedded migrations that are not applied yet. Dry
	// runs report them without applying; real runs apply all of them.
	Pending []PendingMigration
}

// Migrate runs the checksum-guarded migration (concept ch. 4.4 point 3):
//
//  1. verify-before: every already-applied migration in schema_migration_log
//     is hashed against its embedded file; a missing or modified file aborts
//     the run before goose executes anything (ADR-010);
//  2. goose applies all pending migrations while holding the PostgreSQL
//     advisory lock (concurrent runs serialize);
//  3. record-after: every applied migration is recorded with version, file
//     hash, timestamp and duration, and applied migrations that were missing
//     from the log are re-recorded from goose's bookkeeping.
//
// With dryRun set, nothing is written: checksums are still verified and the
// result reports the migrations that would be applied or re-recorded.
func (r *Runner) Migrate(ctx context.Context, dryRun bool) (*Result, error) {
	srcs, err := listSources(r.fsys)
	if err != nil {
		return nil, fmt.Errorf("migrate: read embedded migrations: %w", err)
	}

	logRows, err := r.readChecksumLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: read checksum log: %w", err)
	}
	if err := verifyApplied(r.fsys, logRows, srcs); err != nil {
		return nil, err
	}

	gooseApplied, err := r.readGooseApplied(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: read %s: %w", gooseTable, err)
	}

	res := &Result{DryRun: dryRun, Verified: len(logRows)}
	if dryRun {
		res.Pending, err = pendingMigrations(srcs, gooseApplied)
		if err != nil {
			return nil, err
		}
		// Like a real run, a dry run refuses applied-but-untraceable
		// migrations and reports the rows that would be re-recorded.
		missing, err := r.findUnlogged(ctx, srcs, logRows)
		if err != nil {
			return nil, err
		}
		for _, m := range missing {
			if s, ok := findSource(srcs, m.Version); ok {
				res.Recovered = append(res.Recovered, RecoveredMigration{Version: m.Version, Path: s.Path})
			}
		}
		return res, nil
	}

	// The provider parses migrations lazily and applies pending ones in
	// version order, one transaction per migration, while holding the
	// session advisory lock created in Open.
	provider, err := goose.NewProvider(goose.DialectPostgres, r.db, r.fsys,
		goose.WithSessionLocker(r.locker),
		goose.WithSlog(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	if err != nil {
		return nil, fmt.Errorf("migrate: create goose provider: %w", err)
	}

	applied, err := provider.Up(ctx)
	if err != nil {
		// goose applies migrations one by one; the ones that already
		// committed before the failure must still land in the checksum log.
		var partial *goose.PartialError
		if errors.As(err, &partial) {
			if recErr := r.recordApplied(ctx, srcs, partial.Applied); recErr != nil {
				return nil, errors.Join(
					fmt.Errorf("migrate: apply migrations: %w", err),
					fmt.Errorf("migrate: record partially applied migrations: %w", recErr),
				)
			}
		}
		return nil, fmt.Errorf("migrate: apply migrations: %w", err)
	}
	if len(applied) > 0 {
		if err := r.recordApplied(ctx, srcs, applied); err != nil {
			return nil, err
		}
		for _, m := range applied {
			res.Applied = append(res.Applied, AppliedMigration{
				Version:  m.Source.Version,
				Path:     m.Source.Path,
				Duration: m.Duration,
			})
		}
	}

	// Close the crash window: a migration goose committed but whose log row
	// was never written is recorded from goose's bookkeeping on the next
	// run, so its checksum is protected from then on. The re-read excludes
	// the rows just recorded above from the recovery set.
	logRows, err = r.readChecksumLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: read checksum log: %w", err)
	}
	recovered, err := r.recordUnlogged(ctx, srcs, logRows)
	if err != nil {
		return nil, err
	}
	res.Recovered = recovered
	return res, nil
}

// tableExists reports whether the (search-path resolved) relation exists.
func (r *Runner) tableExists(ctx context.Context, name string) (bool, error) {
	var reg *string
	if err := r.db.QueryRowContext(ctx, "SELECT to_regclass($1)", name).Scan(&reg); err != nil {
		return false, err
	}
	return reg != nil, nil
}

// logRow is one row of the checksum log.
type logRow struct {
	Version  int64
	FileHash string
}

// readChecksumLog returns the checksum-log rows in version order. On a
// database that has never been migrated the table does not exist yet (the
// first migration creates it) and the empty set is returned.
func (r *Runner) readChecksumLog(ctx context.Context) ([]logRow, error) {
	exists, err := r.tableExists(ctx, checksumLogTable)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, "SELECT version, file_hash FROM "+checksumLogTable+" ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []logRow
	for rows.Next() {
		var row logRow
		if err := rows.Scan(&row.Version, &row.FileHash); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// readGooseApplied returns the versions goose records as applied, keyed by
// version, with goose's recorded timestamp. If goose has never run (version
// table absent) the map is empty.
func (r *Runner) readGooseApplied(ctx context.Context) (map[int64]time.Time, error) {
	exists, err := r.tableExists(ctx, gooseTable)
	if err != nil {
		return nil, err
	}
	if !exists {
		return map[int64]time.Time{}, nil
	}
	rows, err := r.db.QueryContext(ctx,
		"SELECT version_id, tstamp FROM "+gooseTable+" WHERE version_id > 0 AND is_applied = true")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64]time.Time)
	for rows.Next() {
		var v int64
		var t time.Time
		if err := rows.Scan(&v, &t); err != nil {
			return nil, err
		}
		out[v] = t
	}
	return out, rows.Err()
}

// recordApplied writes the checksum-log row for every migration goose applied
// in this run: version, SHA-256 of the embedded file content, timestamp
// (now()) and duration. Duplicate versions are ignored — the log is
// write-once per version.
func (r *Runner) recordApplied(ctx context.Context, srcs []source, applied []*goose.MigrationResult) error {
	if len(applied) == 0 {
		return nil
	}
	// The checksum-log table is created by the first migration of the set
	// (ADR-010). If it is missing, the migration set did not bootstrap it
	// and recording cannot work — say so instead of failing on a raw
	// missing-relation error.
	exists, err := r.tableExists(ctx, checksumLogTable)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("migrate: %s does not exist after applying migrations — the first migration of the set must create it (see db/migrations/00001_schema_migration_log.sql)", checksumLogTable)
	}
	for _, m := range applied {
		if m.Source == nil {
			continue
		}
		src, ok := findSource(srcs, m.Source.Version)
		if !ok {
			return fmt.Errorf("migrate: internal error: applied migration version %d not found in the embedded files", m.Source.Version)
		}
		hash, err := fileHash(r.fsys, src.Path)
		if err != nil {
			return err
		}
		if _, err := r.db.ExecContext(ctx,
			"INSERT INTO "+checksumLogTable+" (version, file_hash, duration_ms) VALUES ($1, $2, $3) ON CONFLICT (version) DO NOTHING",
			m.Source.Version, hash, m.Duration.Milliseconds()); err != nil {
			return fmt.Errorf("migrate: record migration %q (version %d) in %s: %w", src.Path, m.Source.Version, checksumLogTable, err)
		}
	}
	return nil
}

// unloggedMigration is an applied migration (per goose's bookkeeping) that is
// missing from the checksum log, together with goose's recorded timestamp.
// Such rows appear when a run crashed between goose's commit of a migration
// and the checksum-log insert.
type unloggedMigration struct {
	Version   int64
	AppliedAt time.Time
}

// findUnlogged returns the applied migrations missing from the checksum log,
// in version order. An applied version that is missing from the embedded
// files as well is treated as tampering and aborts the run (ADR-010).
func (r *Runner) findUnlogged(ctx context.Context, srcs []source, logged []logRow) ([]unloggedMigration, error) {
	gooseApplied, err := r.readGooseApplied(ctx)
	if err != nil {
		return nil, err
	}
	if len(gooseApplied) == 0 {
		return nil, nil
	}
	loggedSet := make(map[int64]bool, len(logged))
	for _, row := range logged {
		loggedSet[row.Version] = true
	}
	versions := make([]int64, 0, len(gooseApplied))
	for v := range gooseApplied {
		if !loggedSet[v] {
			versions = append(versions, v)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	out := make([]unloggedMigration, 0, len(versions))
	for _, v := range versions {
		if _, ok := findSource(srcs, v); !ok {
			return nil, fmt.Errorf(
				"migrate: migration version %d is recorded as applied in %s but exists neither in the embedded files nor in %s — refusing to continue (ADR-010)",
				v, gooseTable, checksumLogTable)
		}
		out = append(out, unloggedMigration{Version: v, AppliedAt: gooseApplied[v]})
	}
	return out, nil
}

// recordUnlogged re-records applied migrations that are missing from the
// checksum log, using the timestamp goose recorded at apply time (the
// duration of such a recovered row is unknown and stays NULL). Rows that a
// dry run would merely report are actually written here.
func (r *Runner) recordUnlogged(ctx context.Context, srcs []source, logged []logRow) ([]RecoveredMigration, error) {
	missing, err := r.findUnlogged(ctx, srcs, logged)
	if err != nil {
		return nil, err
	}
	recovered := make([]RecoveredMigration, 0, len(missing))
	for _, m := range missing {
		src, _ := findSource(srcs, m.Version)
		hash, err := fileHash(r.fsys, src.Path)
		if err != nil {
			return nil, err
		}
		if _, err := r.db.ExecContext(ctx,
			"INSERT INTO "+checksumLogTable+" (version, file_hash, applied_at, duration_ms) VALUES ($1, $2, $3, NULL) ON CONFLICT (version) DO NOTHING",
			m.Version, hash, m.AppliedAt); err != nil {
			return nil, fmt.Errorf("migrate: record recovered migration %q (version %d) in %s: %w", src.Path, m.Version, checksumLogTable, err)
		}
		recovered = append(recovered, RecoveredMigration{Version: m.Version, Path: src.Path})
	}
	return recovered, nil
}
