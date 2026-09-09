// Package postgres is the PostgreSQL data-access home of the adapters layer
// (WP-1a.05, ADR-009): the pgx connection pool every persistence adapter
// opens, the transaction boundary helper that enforces the concept ch. 5.1
// rule (one domain command, one transaction), and the sqlc-generated query
// code in the gen subpackage.
//
// Access is pgx/v5 directly, without database/sql (ADR-009). The schema is
// owned by the migrate package (WP-1a.04, ADR-010): this package only reads
// and writes what the migrations produced, never DDL.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool defaults (WP-1a.05). They are constants of this package so every
// caller gets the same behaviour; a config knob can be added later if a
// deployment needs different values.
const (
	// connectTimeout bounds establishing a single connection, including the
	// TCP/TLS handshake and the startup ping. pgxpool keeps it as the
	// per-connection default for the whole lifetime of the pool.
	connectTimeout = 5 * time.Second

	// minConns keeps the given number of connections warm. 1 avoids the
	// cold-start latency of the first query after idle time while staying
	// cheap for the MVP's single-instance deployments.
	minConns int32 = 1

	// maxConns caps the pool. pgxpool's own default would scale with the
	// host CPU count; an explicit cap keeps database load predictable and
	// is the starting point for the tuning in concept ch. 17.3.
	maxConns int32 = 10
)

// NewPool opens a pgx connection pool for databaseURL without requiring the
// database to be reachable right now: pgx connects lazily, so the pool is
// usable even while the database is down and every operation — Ping
// included — recovers on its own once the database is back. WP-1a.07 uses
// this for the server: readiness is what reports a down database (red
// /health/ready, green /health/live), the server must not refuse to start
// because of it (concept ch. 16.3). The caller owns the pool and must Close
// it for a clean shutdown: pool.Close() waits for in-flight queries, then
// closes every connection (concept ch. 5.2: no work is cut off
// mid-transaction).
func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("postgres: database url is empty")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse database url: %w", err)
	}
	cfg.ConnConfig.ConnectTimeout = connectTimeout
	cfg.MinConns = minConns
	cfg.MaxConns = maxConns

	// pgx scans timestamptz values into time.Time in the local time zone
	// unless the timestamp codec carries an explicit scan location. The
	// walking skeleton stores every timestamp as timestamptz UTC and reads
	// it back as UTC (ARCH-001 §1: "all timestamps timestamptz UTC"); the
	// read contract renders RFC 3339 UTC on the wire (ARCH-001 §4), so the
	// scan location is pinned to UTC here, at the data-access home, instead
	// of leaking the host time zone through the application layer into the
	// API responses.
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pinUTCScan(conn.TypeMap(), pgtype.TimestampOID)
		pinUTCScan(conn.TypeMap(), pgtype.TimestamptzOID)
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: create pool: %w", err)
	}
	return pool, nil
}

// pinUTCScan re-registers the timestamp codec of oid on m with a private
// copy whose scan location is UTC. The codecs of the pgtype default map
// are shared, process-wide instances that every connection's type map
// references — mutating one in place would race the concurrent scans of
// other connections (the -race suite proved it) — so the connection's own
// map gets a copy instead. A missing codec is not an error: the map simply
// does not know the oid.
func pinUTCScan(m *pgtype.Map, oid uint32) {
	dt, ok := m.TypeForOID(oid)
	if !ok {
		return
	}
	switch c := dt.Codec.(type) {
	case *pgtype.TimestampCodec:
		clone := *c
		clone.ScanLocation = time.UTC
		m.RegisterType(&pgtype.Type{Name: dt.Name, OID: dt.OID, Codec: &clone})
	case *pgtype.TimestamptzCodec:
		clone := *c
		clone.ScanLocation = time.UTC
		m.RegisterType(&pgtype.Type{Name: dt.Name, OID: dt.OID, Codec: &clone})
	}
}

// OpenPool opens a pgx connection pool for databaseURL and verifies with a
// startup ping that the database is reachable, so configuration errors
// surface at construction time — the same behaviour migrate.Open has
// (WP-1a.04). Callers that must keep running while the database is down
// (the server's readiness probes, WP-1a.07) use NewPool instead.
func OpenPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := NewPool(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	// Startup health check. Each connection attempt is bounded by
	// connectTimeout; the overall attempt by ctx.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: connect to database: %w", err)
	}
	return pool, nil
}
