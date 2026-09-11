// Package observability samples the §16.2 current-state gauge families that
// have no event recorder and sets them on the process metrics registry
// (implementation concept ch. 16.2, ARCH-007 §5, WP-6.08/6.12 follow-up /
// DEV-138). The HTTP, source and outbox families are written at their event
// points (the httpapi middleware, the worker source jobs, the outbox relay);
// the gauges whose value is "how the world is right now" — the database size
// and pool, the due-job backlog age, the signal triage counts, the pending
// notification retry age and the per-source data age — have no such point and
// are instead sampled from the database and the connection pool on a periodic
// pass. Without this pass those families are declared (their HELP/TYPE render)
// but never carry a value, so the exposition under-reports against §16.2.
//
// The collector writes only families RegisterStandard already declares: it
// references the canonical names/help of internal/platform/metrics, so a gauge
// can never be introduced here with a drifting vocabulary. A collection pass
// is best-effort; a failed query is returned (and logged by Run) without
// touching the gauges of the other families.
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/metrics"
)

// DefaultCollectInterval is the sampling cadence of a metrics Collector when
// Run is called with a non-positive interval. It is deliberately coarse: the
// sampled values change slowly (database size, backlog age, data age) and a
// private deployment scrapes /metrics far less often than this.
const DefaultCollectInterval = 30 * time.Second

// gaugeFamilies are the §16.2 gauge families this package owns. It is the
// regression guard's reference set: every declared gauge family must be either
// sampled here or written at an event point (http_inflight by the middleware,
// jobs_queue_depth by the outbox relay). A family named here must correspond
// to a collect step below.
var gaugeFamilies = []string{
	metrics.NameDatabaseConnections,
	metrics.NameDatabaseSizeBytes,
	metrics.NameJobsOldestAge,
	metrics.NameSignalsOpenByPriority,
	metrics.NameSignalsSLARemaining,
	metrics.NameSignalsUnassigned,
	metrics.NameNotificationsRetryAge,
	metrics.NameSourceDataAge,
}

// GaugeFamilies returns the names of the §16.2 gauge families the collector
// samples. The slice is a copy: a caller cannot mutate the reference set.
func GaugeFamilies() []string { return append([]string(nil), gaugeFamilies...) }

// priorities is the signal priority vocabulary the per-priority gauges emit.
// signals_open_by_priority always carries one series per priority (a zero
// count is a true count); the other per-priority series are emitted only when
// observed.
var priorities = []domain.Priority{
	domain.PriorityP1,
	domain.PriorityP2,
	domain.PriorityP3,
	domain.PriorityP4,
}

// openSignalsPredicate is the SQL predicate of an open signal: every status
// that is not a closed ch. 6.3 state (domain.SignalStatus.IsClosed —
// resolved | accepted | not_affected). The literals mirror the domain
// vocabulary; the set is closed and stable.
const openSignalsPredicate = `status NOT IN ('resolved', 'accepted', 'not_affected')`

// Collector samples the §16.2 gauge families of this package from a pgx pool
// and sets them on one metrics registry. It holds no state between passes; the
// zero value is not usable — construct it with NewCollector.
type Collector struct {
	pool   *pgxpool.Pool
	reg    *metrics.Registry
	logger *slog.Logger
}

// NewCollector binds a collector to the pool it samples and the registry it
// writes. pool and reg must not be nil; a nil logger falls back to a silent
// logger (the tests and registries that do not care).
func NewCollector(pool *pgxpool.Pool, reg *metrics.Registry, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Collector{pool: pool, reg: reg, logger: logger}
}

// Run samples once immediately and then on every interval until ctx is done.
// A non-positive interval falls back to DefaultCollectInterval. A failed pass
// is logged and retried on the next tick: a database that is down must not
// stop the sampler (ch. 16.3 — readiness, not liveness, reflects the DB).
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	if c == nil || c.pool == nil || c.reg == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultCollectInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		c.collectOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// collectOnce runs one pass and logs a failure (unless the context is already
// cancelled, when the error is expected and not worth a log line).
func (c *Collector) collectOnce(ctx context.Context) {
	if err := c.Collect(ctx); err != nil && ctx.Err() == nil {
		c.logger.Warn("metrics gauge collection failed", slog.Any("error", err))
	}
}

// Collect runs one sampling pass: every §16.2 gauge family of this package is
// refreshed. The first failed query aborts the pass with that error — the
// families collected before it keep their fresh value, the others keep the
// previous pass's value.
func (c *Collector) Collect(ctx context.Context) error {
	if c == nil || c.pool == nil || c.reg == nil {
		return nil
	}
	if err := c.collectDatabase(ctx); err != nil {
		return err
	}
	if err := c.collectJobs(ctx); err != nil {
		return err
	}
	if err := c.collectSignals(ctx); err != nil {
		return err
	}
	if err := c.collectNotifications(ctx); err != nil {
		return err
	}
	if err := c.collectSourceDataAge(ctx); err != nil {
		return err
	}
	return nil
}

// collectDatabase sets database_connections (the connections the pool holds)
// and database_size_bytes (the on-disk size of the app database).
func (c *Collector) collectDatabase(ctx context.Context) error {
	c.reg.Gauge(metrics.NameDatabaseConnections, metrics.HelpDatabaseConnections).
		Set(float64(c.pool.Stat().TotalConns()))

	var sizeBytes int64
	if err := c.pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&sizeBytes); err != nil {
		return fmt.Errorf("observability: read database size: %w", err)
	}
	c.reg.Gauge(metrics.NameDatabaseSizeBytes, metrics.HelpDatabaseSizeBytes).Set(float64(sizeBytes))
	return nil
}

// collectJobs sets jobs_oldest_age_seconds: the age of the oldest due outbox
// job — the waiting (pending) row whose available_at is furthest in the past,
// zero when the due backlog is empty.
func (c *Collector) collectJobs(ctx context.Context) error {
	var ageSeconds float64
	const q = `
		SELECT COALESCE(EXTRACT(EPOCH FROM (now() - min(available_at))), 0)::double precision
		FROM outbox
		WHERE status = 'pending' AND available_at <= now()`
	if err := c.pool.QueryRow(ctx, q).Scan(&ageSeconds); err != nil {
		return fmt.Errorf("observability: read oldest due outbox job: %w", err)
	}
	c.reg.Gauge(metrics.NameJobsOldestAge, metrics.HelpJobsOldestAge).Set(ageSeconds)
	return nil
}

// collectSignals sets signals_open_by_priority (one series per priority),
// signals_unassigned (open signals without an owner) and
// signals_sla_remaining_seconds (the tightest open SLA clock per priority,
// with the pause adjustment of ch. 9.4).
func (c *Collector) collectSignals(ctx context.Context) error {
	openByPriority := map[string]float64{}
	for _, p := range priorities {
		openByPriority[string(p)] = 0
	}
	rows, err := c.pool.Query(ctx, `
		SELECT priority, count(*)
		FROM risk_signals
		WHERE `+openSignalsPredicate+`
		GROUP BY priority`)
	if err != nil {
		return fmt.Errorf("observability: read open signals by priority: %w", err)
	}
	for rows.Next() {
		var priority string
		var count int64
		if err := rows.Scan(&priority, &count); err != nil {
			rows.Close()
			return fmt.Errorf("observability: scan open signals by priority: %w", err)
		}
		if _, known := openByPriority[priority]; known {
			openByPriority[priority] = float64(count)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("observability: iterate open signals by priority: %w", err)
	}
	for _, p := range priorities {
		c.reg.Gauge(metrics.NameSignalsOpenByPriority, metrics.HelpSignalsOpenByPriority).
			With(metrics.Labels{"priority": string(p)}).Set(openByPriority[string(p)])
	}

	var unassigned int64
	if err := c.pool.QueryRow(ctx, `
		SELECT count(*) FROM risk_signals
		WHERE owner IS NULL AND `+openSignalsPredicate).Scan(&unassigned); err != nil {
		return fmt.Errorf("observability: read unassigned open signals: %w", err)
	}
	c.reg.Gauge(metrics.NameSignalsUnassigned, metrics.HelpSignalsUnassigned).Set(float64(unassigned))

	// The effective deadline of an open clock (ch. 9.4) is
	// deadline_at + paused_seconds + (now - paused_at) while paused; the
	// expression below evaluates remaining = effective_deadline - now for
	// both the running (paused_at NULL) and the paused clock.
	slaRows, err := c.pool.Query(ctx, `
		SELECT s.priority, min(EXTRACT(EPOCH FROM (
			c.deadline_at
			+ make_interval(secs => c.paused_seconds)
			+ COALESCE(now() - c.paused_at, interval '0')
			- now()
		)))::double precision
		FROM sla_clocks c
		JOIN risk_signals s ON s.id = c.signal_id
		WHERE c.fulfilled_at IS NULL AND s.`+openSignalsPredicate+`
		GROUP BY s.priority`)
	if err != nil {
		return fmt.Errorf("observability: read tightest open SLA clock: %w", err)
	}
	for slaRows.Next() {
		var priority string
		var remaining float64
		if err := slaRows.Scan(&priority, &remaining); err != nil {
			slaRows.Close()
			return fmt.Errorf("observability: scan tightest open SLA clock: %w", err)
		}
		c.reg.Gauge(metrics.NameSignalsSLARemaining, metrics.HelpSignalsSLARemaining).
			With(metrics.Labels{"priority": priority}).Set(remaining)
	}
	if err := slaRows.Err(); err != nil {
		return fmt.Errorf("observability: iterate tightest open SLA clock: %w", err)
	}
	return nil
}

// collectNotifications sets notifications_retry_age_seconds: the age of the
// oldest notification still awaiting delivery (status pending), zero when none
// is waiting.
func (c *Collector) collectNotifications(ctx context.Context) error {
	var ageSeconds float64
	const q = `
		SELECT COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at))), 0)::double precision
		FROM notifications
		WHERE status = 'pending'`
	if err := c.pool.QueryRow(ctx, q).Scan(&ageSeconds); err != nil {
		return fmt.Errorf("observability: read pending notification retry age: %w", err)
	}
	c.reg.Gauge(metrics.NameNotificationsRetryAge, metrics.HelpNotificationsRetryAge).Set(ageSeconds)
	return nil
}

// collectSourceDataAge sets source_data_age_seconds per source: the age of the
// newest record, derived from the source's latest successful run — the
// committed incremental cursor's last_modified when present, the run's
// finished_at otherwise (ARCH-002 §5, the source-monitor data-age basis). A
// source without a successful run has no data age and no series; the age is
// clamped at zero (a basis in the future means "not stale", never negative).
func (c *Collector) collectSourceDataAge(ctx context.Context) error {
	rows, err := c.pool.Query(ctx, `
		SELECT s.id::text, s.type, r.finished_at, r.cursor_after, now()
		FROM sources s
		JOIN LATERAL (
			SELECT finished_at, cursor_after
			FROM source_runs
			WHERE source_id = s.id AND status = 'succeeded'
			ORDER BY started_at DESC
			LIMIT 1
		) r ON true`)
	if err != nil {
		return fmt.Errorf("observability: read source data age: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			sourceID   string
			sourceType string
			finishedAt *time.Time
			cursor     []byte
			now        time.Time
		)
		if err := rows.Scan(&sourceID, &sourceType, &finishedAt, &cursor, &now); err != nil {
			return fmt.Errorf("observability: scan source data age: %w", err)
		}
		basis, ok := dataAgeBasis(finishedAt, cursor)
		if !ok {
			continue
		}
		age := now.Sub(basis).Seconds()
		if age < 0 {
			age = 0
		}
		c.reg.Gauge(metrics.NameSourceDataAge, metrics.HelpSourceDataAge).
			With(metrics.Labels{"source_id": sourceID, "source_type": sourceType}).Set(age)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("observability: iterate source data age: %w", err)
	}
	return nil
}

// dataAgeBasis returns the data-age basis of one successful run: the
// last_modified of the committed incremental cursor when it carries one (the
// NVD window end, ch. 8.2), the finished_at otherwise (full-set sources).
// ok=false when neither is present — no basis, no data age.
func dataAgeBasis(finishedAt *time.Time, cursorAfter []byte) (time.Time, bool) {
	if t, has := cursorLastModified(cursorAfter); has {
		return t, true
	}
	if finishedAt != nil && !finishedAt.IsZero() {
		return *finishedAt, true
	}
	return time.Time{}, false
}

// cursorLastModified reads the time of a last-modified cursor — the
// {"last_modified": "<RFC3339>"} shape of the NVD cursor (ARCH-002 §1). A
// cursor without a parseable last_modified member is not a data basis.
func cursorLastModified(cursor json.RawMessage) (time.Time, bool) {
	if len(cursor) == 0 {
		return time.Time{}, false
	}
	var c struct {
		LastModified string `json:"last_modified"`
	}
	if err := json.Unmarshal(cursor, &c); err != nil || c.LastModified == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, c.LastModified)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
