package epss

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/xpera/risksignal/internal/application"
)

// Stable RecordError reason codes of the normaliser (ch. 5.2: error_code +
// human message). A code identifies the failure class on the quarantine
// row; the message adds the payload position and the concrete detail.
const (
	// reasonDocumentGzip: the stored payload does not decompress as a gzip
	// stream (its first bytes are no gzip member). Defensive — the fetch
	// half stores the daily file as served.
	reasonDocumentGzip = "epss.normalize.gzip"
	// reasonRowCSV: a non-comment line is not parseable as a CSV record
	// with the daily file's three columns (cve, epss, percentile) — a
	// broken quoted field or a column count other than 3.
	reasonRowCSV = "epss.normalize.row_csv"
	// reasonInvalidNumber: a present score/percentile is not a decimal
	// numeric literal in [0,1] — the EPSS probability range (ARCH-002 §3).
	reasonInvalidNumber = "epss.normalize.invalid_number"
)

// maxRowBytes bounds one CSV line of the decompressed stream. Daily-file
// rows are a few dozen bytes; the bound only guards against a pathological
// unbounded line (bufio.Scanner default is 64 KiB — raised for headroom,
// not because real rows come close).
const maxRowBytes = 1 << 20

// Normalize is the normalise half of the EPSS port (ARCH-002 §2.3, ADR-013,
// ch. 8.4): it stream-decompresses the stored daily file and emits one
// epss_current row per data line into the bulk writer the application
// handed over through NormalizeInput.EpssBulk — the persistence half loads
// them with TRUNCATE + COPY in the pass transaction. The decompressed file
// never materialises in memory: the gzip stream is read line by line and
// each line is parsed as the single CSV record it is.
//
// Missing values are recorded as absent, never as a zero (ch. 8.4): a data
// line that is missing any of its three values (cve, epss, percentile) is
// not loaded — the CVE stays absent from the current set instead of being
// stored with a fabricated zero percentile or score. Absence is the
// file's own data state, not an error, so it is neither counted nor
// quarantined. A line that is *present but invalid* — not a 3-column CSV
// record, or a score/percentile that is not a decimal in [0,1] — is
// isolated through sink.RecordError (position "line N", a stable reason
// code and the SHA-256 of the offending line) and never aborts the pass
// (ch. 8.1 step 5). Only a failing bulk write — an infrastructure failure
// — and a broken gzip stream abort it.
//
// NormalizeResult.Records is the number of rows streamed into the bulk
// writer — the copied-row count the run records as the measured daily row
// count (ADR-013: measured once, not fixed in prose).
func (*Adapter) Normalize(ctx context.Context, in application.NormalizeInput, sink application.NormalizeSink) (application.NormalizeResult, error) {
	res := application.NormalizeResult{}
	if in.EpssBulk == nil {
		// The port specialisation is additive and nil-safe for the other
		// sources (they never read the field), but the EPSS adapter
		// requires its writer: without it nothing would load and the run
		// would complete as if the set had been replaced — an
		// infrastructure error instead (the wiring that populates
		// NormalizeInput.EpssBulk is a source-run completion follow-up).
		return res, fmt.Errorf("epss: normalize: the source-run wiring must hand the EPSS bulk writer (NormalizeInput.EpssBulk); nothing was loaded")
	}

	gr, err := gzip.NewReader(bytes.NewReader(in.Payload))
	if err != nil {
		// A payload whose first bytes are no gzip member cannot be
		// streamed further — the whole document is isolated (position
		// "document", hashed) and the pass ends as a counted, non-fatal
		// error (ch. 8.6, ch. 8.1 step 5).
		if serr := sink.RecordError(ctx, application.RecordError{
			Position:    "document",
			Reason:      fmt.Sprintf("%s: the payload does not decompress as a gzip stream: %v", reasonDocumentGzip, err),
			PayloadHash: sha256Hex(in.Payload),
		}); serr != nil {
			return res, fmt.Errorf("epss: normalize: isolate document: %w", serr)
		}
		res.Errors++
		return res, nil
	}
	defer gr.Close()

	sc := bufio.NewScanner(gr)
	sc.Buffer(make([]byte, 0, 64*1024), maxRowBytes)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue // blank line or the file's "#model_version…" comment
		}

		rec, err := parseRow(raw)
		if err != nil {
			if serr := emitRecordError(ctx, sink, &res, line, raw, reasonRowCSV, err.Error()); serr != nil {
				return res, serr
			}
			continue
		}
		if allFieldsEmpty(rec) {
			continue // a stray row of empty columns — absent, not an error
		}
		if len(rec) == 3 && rec[0] == "cve" {
			continue // the "cve,epss,percentile" header line
		}
		if len(rec) != 3 {
			if serr := emitRecordError(ctx, sink, &res, line, raw, reasonRowCSV,
				fmt.Sprintf("line %d carries %d columns, want 3 (cve, epss, percentile)", line, len(rec))); serr != nil {
				return res, serr
			}
			continue
		}

		cve, score, percentile := strings.TrimSpace(rec[0]), strings.TrimSpace(rec[1]), strings.TrimSpace(rec[2])
		if cve == "" || score == "" || percentile == "" {
			// ch. 8.4: a missing value is recorded as absent — the row is
			// not loaded, and no zero is fabricated for it.
			continue
		}
		if !validEPSSNumber(score) {
			if serr := emitRecordError(ctx, sink, &res, line, raw, reasonInvalidNumber,
				fmt.Sprintf("score %q of %s is not a decimal in [0,1]", score, cve)); serr != nil {
				return res, serr
			}
			continue
		}
		if !validEPSSNumber(percentile) {
			if serr := emitRecordError(ctx, sink, &res, line, raw, reasonInvalidNumber,
				fmt.Sprintf("percentile %q of %s is not a decimal in [0,1]", percentile, cve)); serr != nil {
				return res, serr
			}
			continue
		}

		if err := in.EpssBulk.WriteEpssRow(ctx, application.EpssRow{CveID: cve, Score: score, Percentile: percentile}); err != nil {
			// A failing persistence write aborts the pass (ch. 8.1 step
			// 5: infrastructure failures are fatal — the run rolls back
			// with nothing partially committed).
			return res, fmt.Errorf("epss: normalize: write row %d (%s): %w", line, cve, err)
		}
		res.Records++
	}
	if err := sc.Err(); err != nil {
		// A mid-stream read failure (a truncated or checksum-broken gzip
		// stream) is an infrastructure failure: nothing of the pass may be
		// committed as a load.
		return res, fmt.Errorf("epss: normalize: read gzip stream: %w", err)
	}
	return res, nil
}

// parseRow parses one non-comment line as a single CSV record. The daily
// file's data lines are plain "cve,epss,percentile" rows, but the real CSV
// reader is used so that quoted content is handled correctly instead of by
// naive comma-splitting. The field-count check is left to the caller (blank
// and header rows are skipped before it); CSV syntax errors — broken
// quoting — surface here.
func parseRow(line string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(line))
	return r.Read()
}

// allFieldsEmpty reports whether a parsed record consists only of empty
// fields — a stray blank row of a variable field count.
func allFieldsEmpty(rec []string) bool {
	for _, f := range rec {
		if strings.TrimSpace(f) != "" {
			return false
		}
	}
	return true
}

// validEPSSNumber validates one score/percentile value of the daily file:
// it must be a numeric literal whose value lies in [0,1], the EPSS
// probability range (ARCH-002 §3). The value is parsed with the exact
// conversion the COPY path applies — pgtype.Numeric, exponent-aware: the
// real daily file renders very small percentiles in scientific notation
// ("7e-05"), a literal PostgreSQL's numeric column accepts, so a plain
// decimal-only scan would wrongly reject it — so an accepted row is
// COPY-ready by construction: the bulk writer's conversion cannot fail on
// it. A *missing* value never reaches this check: it is recorded as absent
// (ch. 8.4), never as a zero.
func validEPSSNumber(v string) bool {
	n, err := parseDecimal(v)
	if err != nil {
		return false
	}
	if !n.Valid {
		return false
	}
	f, err := n.Float64Value()
	if err != nil || !f.Valid {
		return false
	}
	return f.Float64 >= 0 && f.Float64 <= 1
}

// parseDecimal parses one numeric literal into pgtype.Numeric — the exact
// conversion the bulk writer applies before the COPY (the generated
// InsertEpssRowsParams carry pgtype.Numeric). pgtype's plain Scan rejects
// scientific notation, which the daily file uses for very small
// percentiles ("7e-05"); ScanScientific handles exactly those and rejects
// plain decimals, so the two parsers are selected by the literal's form.
func parseDecimal(v string) (pgtype.Numeric, error) {
	var n pgtype.Numeric
	var err error
	if strings.ContainsAny(v, "eE") {
		err = n.ScanScientific(v)
	} else {
		err = n.Scan(v)
	}
	return n, err
}

// emitRecordError isolates one failed data line through the sink and counts
// it (ch. 8.6): the position is the 1-based line of the decompressed file,
// the payload hash is the SHA-256 of the raw line — re-addressable on
// reprocess. An isolated error is counted, not fatal.
func emitRecordError(ctx context.Context, sink application.NormalizeSink, res *application.NormalizeResult, line int, raw, code, detail string) error {
	if err := sink.RecordError(ctx, application.RecordError{
		Position:    fmt.Sprintf("line %d", line),
		Reason:      fmt.Sprintf("%s: %s", code, detail),
		PayloadHash: sha256Hex([]byte(raw)),
	}); err != nil {
		return fmt.Errorf("epss: normalize: isolate row %d: %w", line, err)
	}
	res.Errors++
	return nil
}

// sha256Hex hashes the canonical bytes of an offending line/slice
// (RecordError.PayloadHash — a hash, never the payload itself).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// compile-time check that the adapter satisfies the shared port.
var _ application.SourcePort = (*Adapter)(nil)
