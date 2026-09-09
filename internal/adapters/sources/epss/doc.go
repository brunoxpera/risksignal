// Package epss implements the FIRST EPSS daily-set source adapter
// (ARCH-002 §2.3, WP-2.07): both halves of the shared SourcePort for the
// "epss" source type — the daily file fetch and the normaliser that
// stream-decompresses the file and loads the parsed rows into the
// epss_current bulk set.
//
// # Fetch semantics
//
// Fetch reads the source descriptor and GETs the daily file of the injected
// clock's UTC date (ARCH-002 §1 endpoint, e.g.
// https://epss.empiricalsecurity.com):
// <endpoint>/epss_scores-YYYY-MM-DD.csv.gz — the date comes from
// clock.Now(), never the wall clock (ch. 7.2). The raw record is the file
// itself, not its rows (ADR-013): the verbatim compressed bytes are stored
// unchanged and hashed (SHA-256) into FetchOutput.ContentHash; the external
// id is the file name ("epss_scores-2026-09-09.csv.gz") and the cursor
// stays nil — a full-set source advances none (CursorKindNone). A
// rate-limited response (429/503) is a rate limit, not a source fault
// (ch. 14.2): Fetch returns FetchMeta{RateLimited: true, RetryAfter: …}
// with no error (Retry-After parsed as seconds or an HTTP date; 0 when
// absent). Any other non-200 status is an error.
//
// # Content-hash no-op (same day, unchanged file)
//
// The daily file of one day is one raw-record identity: re-running the
// same day's unchanged file (the same bytes as the last committed raw
// record of the source) is a successful no-op run, not a re-store (ch. 8.3,
// ARCH-002 §2.3: FetchMeta.NoChange, counters all 0, no reload). The
// adapter is persistence-free and never reads the database: it compares the
// fetched file's hash against the content hash the fetch use case hands
// back through sources.config.last_content_hash (maintained after each
// committed run; source-run wiring follow-up — absent today, every fetch
// returns a full output and the no-op signal activates with that wiring).
// A new day's file has a new external id and a new hash: it is stored and
// replaces the whole set on the normalise side.
//
// # Normalise semantics — the bulk path (EPSS is the documented deviation)
//
// Normalize does not emit domain objects: EPSS's normalise output is
// epss_current rows (ch. 8.4, ADR-013, ARCH-002 §1). The application hands
// the adapter a BulkRowWriter through NormalizeInput.EpssBulk (nil-safe for
// the other sources; an error in this adapter when absent — nothing may be
// loaded silently); the normaliser stream-decompresses the stored gzip file
// (the decompressed file never materialises in memory, ch. 8.4) and
// streams one parsed row per data line into the writer. The persistence
// half of the writer batches the pass's rows and loads them into
// epss_current with one pgx COPY — TRUNCATE + COPY in the pass
// transaction, committed together, so the swap of the daily set is atomic
// (ADR-013: a reader sees either the complete old set or the complete new
// one). The writer stamps model_version (the daily file's date) and
// loaded_at (the run's fetch instant from the injected clock); the adapter
// returns the number of streamed rows in NormalizeResult.Records — the
// measured daily row count of the run's counters/metric (ADR-013: measured
// once, not fixed in prose).
//
// The daily file opens with a "#" comment line (model_version/score_date)
// and a "cve,epss,percentile" header; data lines are the plain
// "CVE-…,<score>,<percentile>" rows. Missing values are recorded as
// absent, never as a zero (ch. 8.4): a data line missing any of its three
// values is not loaded — the CVE stays absent from the current set instead
// of being stored with a fabricated zero percentile or score — and that
// absence is the file's own data state, not an error (neither counted nor
// quarantined). A line that is present but invalid (not a 3-column CSV
// record, or a score/percentile that is not a decimal in [0,1]) is
// isolated through sink.RecordError — position ("line N"), a stable reason
// code and the SHA-256 of the offending line — and never aborts the pass
// (ch. 8.1 step 5); the healthy rows keep flowing. Only a failing bulk
// write and a broken gzip stream (infrastructure) abort it.
//
// # Determinism
//
// One payload normalises to one identical emission: rows stream in file
// order, values travel as the file's own decimal literals (fixed field
// order, no maps) and the score/percentile are validated — never
// rewritten — against the numeric range, so re-running one raw record
// yields the identical row stream and row count.
package epss
