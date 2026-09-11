package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	// pgx registers the "pgx" database/sql driver (ADR-009).
	_ "github.com/jackc/pgx/v5/stdlib"
)

// dbNameMask constrains the throwaway database names this package creates and
// drops, so a name can never smuggle anything into the CREATE/DROP statement.
var dbNameMask = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// TempDatabaseName builds a throwaway database name for the restore test.
func TempDatabaseName(now time.Time) string {
	return "rs_restore_test_" + now.UTC().Format("20060102t150405")
}

// DatabaseURLWithName returns databaseURL with its database name replaced by
// name (the scheme, host, port, credentials and query are preserved).
func DatabaseURLWithName(databaseURL, name string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(databaseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("backup: database url is not a valid connection URL")
	}
	u.Path = "/" + name
	return u.String(), nil
}

// CreateDatabase creates an empty database name on the server of adminURL —
// the throwaway empty instance the restore test restores into. It must be
// reachable on the same server as adminURL (the dump/restore target).
func CreateDatabase(ctx context.Context, adminURL, name string) error {
	if !dbNameMask.MatchString(name) {
		return errors.New("backup: invalid throwaway database name")
	}
	db, err := sql.Open("pgx", adminURL)
	if err != nil {
		return fmt.Errorf("backup: open admin connection: %w", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		return fmt.Errorf("backup: create throwaway database: %w", err)
	}
	return nil
}

// DropDatabase drops name on the server of adminURL. WITH (FORCE) terminates
// any lingering connections (PostgreSQL 13+), so the throwaway instance is
// always reclaimed.
func DropDatabase(ctx context.Context, adminURL, name string) error {
	if !dbNameMask.MatchString(name) {
		return errors.New("backup: invalid throwaway database name")
	}
	db, err := sql.Open("pgx", adminURL)
	if err != nil {
		return fmt.Errorf("backup: open admin connection: %w", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`); err != nil {
		return fmt.Errorf("backup: drop throwaway database: %w", err)
	}
	return nil
}

// openSession opens a single-connection session with a fixed UTC time zone,
// so the row-text hashing in Verify is timezone-stable across source and
// restored instance.
func openSession(ctx context.Context, databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("backup: open connection: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("backup: connect: %w", err)
	}
	if _, err := db.ExecContext(ctx, "SET TIME ZONE 'UTC'"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("backup: set timezone: %w", err)
	}
	return db, nil
}
