package application

// The EPSS bulk row writer (DEV-041, ARCH-002 §1/§2.3/§5, ADR-013): the
// application-side implementation of the BulkRowWriter port the EPSS
// adapter streams its parsed daily-file rows into. The port comment says it
// — BulkRowWriter is the persistence half of the EPSS full-set normalise
// pass, implemented by the application on the pass transaction.
//
// The writer is transaction-scoped: it is constructed over the very
// transaction the pass runs in (the same one the raw-record insert, the
// NormalizeSink writes and the run completion run on), so the daily-set
// swap commits atomically with the run — TRUNCATE epss_current + one pgx
// COPY, committed together or rolled back together (ADR-013: a reader sees
// either the complete old set or the complete new one, and a failing run
// leaves the previous day's set intact).
//
// Rows are buffered as they stream in (the adapter emits one WriteEpssRow
// per data line of the decompressed file; ch. 8.4 keeps the *decompressed
// text* out of memory, the parsed rows of one daily set are a small
// bounded batch) and loaded in one COPY statement when the use case calls
// load after the adapter's Normalize returned — the port deliberately
// exposes no flush method (ARCH-002 §1: WriteEpssRow only), so the load is
// a use-case step, not an adapter concern. The writer stamps model_version
// (the daily file's date, derived from the raw record's external id) and
// loaded_at (the run's clock instant) on every copied row; score and
// percentile travel as the decimal literals of the file (pgtype.Numeric —
// the exact conversion the epss adapter validated against, so a parse
// failure here is unreachable and treated as an infrastructure failure).
//
// A failing TRUNCATE or COPY aborts the pass (ch. 8.1 step 5:
// infrastructure failures are fatal — the run rolls back with nothing
// partially committed and the previous day's set stays readable).

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// epssModelVersionOf derives the model_version stamp of one EPSS load from
// the raw record's external id — the daily file name
// ("epss_scores-2026-09-09.csv.gz", ARCH-002 §2.3) whose date is the daily
// set's model version. An external id that is not the daily-file shape
// falls back to the record's fetch date — defensive; the EPSS adapter
// always names its raw records after the file it fetched.
func epssModelVersionOf(externalID string, fetchedAt time.Time) string {
	const (
		filePrefix = "epss_scores-"
		fileSuffix = ".csv.gz"
	)
	rest, ok := strings.CutPrefix(externalID, filePrefix)
	if ok {
		if name, cut := strings.CutSuffix(rest, fileSuffix); cut {
			if day, err := time.Parse("2006-01-02", name); err == nil {
				return day.Format("2006-01-02")
			}
		}
	}
	return fetchedAt.UTC().Format("2006-01-02")
}

// epssBulkRow is one buffered epss_current row of a pass: the natural key
// plus the score/percentile as the COPY-ready decimals (model_version and
// loaded_at are pass context, stamped by the writer, not per-row values).
type epssBulkRow struct {
	cveID      string
	score      pgtype.Numeric
	percentile pgtype.Numeric
}

// epssBulkWriter implements BulkRowWriter over the pass transaction
// (ARCH-002 §1): rows stream in through WriteEpssRow and the use case loads
// them with load — TRUNCATE + one pgx COPY on the pass transaction — after
// the adapter's Normalize succeeded.
type epssBulkWriter struct {
	tx           Tx // the pass transaction; TRUNCATE + COPY run on it
	modelVersion string
	loadedAt     time.Time
	rows         []epssBulkRow
}

// newEpssBulkWriter binds one pass's writer to its transaction. modelVersion
// is the daily file's date (epssModelVersionOf); loadedAt is the run's
// fetch instant from the injected clock — both stamp every copied row
// (ARCH-002 §3: model_version/loaded_at are run context, not file content).
func newEpssBulkWriter(tx Tx, modelVersion string, loadedAt time.Time) *epssBulkWriter {
	return &epssBulkWriter{tx: tx, modelVersion: modelVersion, loadedAt: loadedAt}
}

// compile-time check that the writer satisfies the port the EPSS adapter
// streams into.
var _ BulkRowWriter = (*epssBulkWriter)(nil)

// WriteEpssRow implements BulkRowWriter: parse the row's decimal literals
// into the COPY-ready numerics and buffer it for the pass's single COPY.
// The epss adapter validated the literals against the exact conversion
// applied here (same dual parser, exponent-aware for the scientific
// notation of tiny percentiles), so a parse failure is unreachable — it is
// an infrastructure failure of the persistence half when it happens.
func (w *epssBulkWriter) WriteEpssRow(ctx context.Context, row EpssRow) error {
	score, err := parseEpssDecimal(row.Score)
	if err != nil {
		return InfraError("epss_bulk", fmt.Errorf("parse score %q of %s: %w", row.Score, row.CveID, err))
	}
	percentile, err := parseEpssDecimal(row.Percentile)
	if err != nil {
		return InfraError("epss_bulk", fmt.Errorf("parse percentile %q of %s: %w", row.Percentile, row.CveID, err))
	}
	w.rows = append(w.rows, epssBulkRow{cveID: row.CveID, score: score, percentile: percentile})
	return nil
}

// load runs the atomic swap of the current set on the pass transaction
// (ARCH-002 §2.3, ADR-013): TRUNCATE epss_current then one pgx COPY of the
// pass's buffered rows (ADR-009: pgx CopyFrom — one round trip for the
// whole set), both inside the pass transaction the caller commits. It
// returns the number of copied rows. A failing statement is an
// infrastructure failure: the caller aborts the pass and the whole
// transaction rolls back, leaving the previous day's set intact and
// readable.
func (w *epssBulkWriter) load(ctx context.Context) (int64, error) {
	if _, err := w.tx.Exec(ctx, "TRUNCATE epss_current"); err != nil {
		return 0, InfraError("epss_bulk", fmt.Errorf("truncate epss_current: %w", err))
	}
	n, err := w.tx.CopyFrom(ctx,
		pgx.Identifier{"epss_current"},
		[]string{"cve_id", "score", "percentile", "model_version", "loaded_at"},
		&epssRowsCopySource{rows: w.rows, modelVersion: w.modelVersion, loadedAt: w.loadedAt},
	)
	if err != nil {
		return 0, InfraError("epss_bulk", fmt.Errorf("copy %d rows into epss_current: %w", len(w.rows), err))
	}
	return n, nil
}

// epssRowsCopySource drives the pgx COPY of one pass: each buffered row
// yields one epss_current tuple with the writer's model_version/loaded_at
// stamps.
type epssRowsCopySource struct {
	rows         []epssBulkRow
	modelVersion string
	loadedAt     time.Time
}

// Next reports whether another row remains.
func (s *epssRowsCopySource) Next() bool { return len(s.rows) > 0 }

// Values returns the next row's tuple and consumes it.
func (s *epssRowsCopySource) Values() ([]any, error) {
	row := s.rows[0]
	s.rows = s.rows[1:]
	return []any{row.cveID, row.score, row.percentile, s.modelVersion, s.loadedAt}, nil
}

// Err reports a source-side failure; the copy path only fails on the
// database side, never here.
func (s *epssRowsCopySource) Err() error { return nil }

// parseEpssDecimal parses one decimal literal of the daily file into the
// pgtype.Numeric the COPY path sends. The epss adapter documents the dual
// parser: pgtype's plain Scan rejects the scientific notation the real file
// uses for very small percentiles ("7e-05"), while ScanScientific handles
// exactly those; the literal's form selects the parser, so an accepted row
// is COPY-ready by construction. The parser mirrors
// internal/adapters/sources/epss.parseDecimal — the adapter validates with
// it, the persistence half converts with it.
func parseEpssDecimal(v string) (pgtype.Numeric, error) {
	var n pgtype.Numeric
	var err error
	if strings.ContainsAny(v, "eE") {
		err = n.ScanScientific(v)
	} else {
		err = n.Scan(v)
	}
	return n, err
}
