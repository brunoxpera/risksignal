package backup

import (
	"context"
	"database/sql"
	"fmt"
)

// hashTables are the tables whose sample rows are hashed and compared between
// the source and the restored instance (the AT-015 sample-row-hash assertion).
// Only tables that carry an `id` column participate; the others are covered by
// the object-count comparison.
var hashTables = []string{
	"risk_signals",
	"matches",
	"evidences",
	"vulnerabilities",
	"raw_records",
	"assets",
	"components",
	"sources",
	"source_runs",
	"audit_events",
	"users",
	"comments",
	"sla_clocks",
	"notifications",
	"legal_holds",
	"retention_runs",
	"exports",
}

// sampleHashLimit bounds the sample-row hash of one table (the first N rows by
// id — "sample-row hashes" of AT-015).
const sampleHashLimit = 1000

// Report is the outcome of the restore-test integrity assertions.
type Report struct {
	// Tables is the number of base tables compared.
	Tables int `json:"tables"`
	// Rows is the summed row count of the source tables.
	Rows int64 `json:"rows"`
	// TableCounts is the per-table source row count.
	TableCounts map[string]int64 `json:"table_counts"`
	// SampleHashes is the sample-row hash per hashed table (source value).
	SampleHashes map[string]string `json:"sample_hashes"`
	// OpenSignals is the source count of open (not closed) signals.
	OpenSignals int64 `json:"open_signals"`
	// AuditRows is the source audit-trail row count.
	AuditRows int64 `json:"audit_rows"`
	// ChainVerified reports whether a populated audit hash chain (if any) was
	// verified consistent end-to-end. It is false when the chain is disabled
	// (all row_hash NULL — the default, ARCH-007 §7 control 3b).
	ChainVerified bool `json:"chain_verified"`
	// Matched reports whether every assertion held.
	Matched bool `json:"matched"`
	// Mismatches lists every failed assertion (empty when Matched).
	Mismatches []string `json:"mismatches"`
}

// Verify compares the source database against the restored instance: schema
// presence, per-table object counts, sample-row hashes, open-signal integrity
// and the audit trail (row count plus an optional hash-chain verification).
// It never writes to either database.
func Verify(ctx context.Context, sourceURL, targetURL string) (Report, error) {
	src, err := openSession(ctx, sourceURL)
	if err != nil {
		return Report{}, err
	}
	defer src.Close()
	tgt, err := openSession(ctx, targetURL)
	if err != nil {
		return Report{}, err
	}
	defer tgt.Close()

	srcTables, err := listTables(ctx, src)
	if err != nil {
		return Report{}, err
	}
	tgtTables, err := listTables(ctx, tgt)
	if err != nil {
		return Report{}, err
	}

	rep := Report{TableCounts: map[string]int64{}, SampleHashes: map[string]string{}}
	for t := range srcTables {
		if !tgtTables[t] {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("schema: table %q is missing in the restored instance", t))
			continue
		}
		srcCount, err := countRows(ctx, src, t)
		if err != nil {
			return Report{}, err
		}
		tgtCount, err := countRows(ctx, tgt, t)
		if err != nil {
			return Report{}, err
		}
		rep.TableCounts[t] = srcCount
		rep.Rows += srcCount
		if srcCount != tgtCount {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("object count %q: source=%d restored=%d", t, srcCount, tgtCount))
		}
	}
	rep.Tables = len(srcTables)
	for _, t := range hashTables {
		if !tgtTables[t] {
			continue
		}
		hasID, err := hasColumn(ctx, src, t, "id")
		if err != nil {
			return Report{}, err
		}
		if !hasID {
			continue
		}
		srcHash, err := sampleHash(ctx, src, t)
		if err != nil {
			return Report{}, err
		}
		tgtHash, err := sampleHash(ctx, tgt, t)
		if err != nil {
			return Report{}, err
		}
		rep.SampleHashes[t] = srcHash
		if srcHash != tgtHash {
			rep.Mismatches = append(rep.Mismatches, fmt.Sprintf("sample-row hash %q differs between source and restored instance", t))
		}
	}

	if err := verifyOpenSignals(ctx, src, tgt, &rep); err != nil {
		return Report{}, err
	}
	if err := verifyAuditChain(ctx, src, tgt, &rep); err != nil {
		return Report{}, err
	}

	rep.Matched = len(rep.Mismatches) == 0
	return rep, nil
}

// listTables returns the set of user base tables in the public schema.
func listTables(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT table_name FROM information_schema.tables
		 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		return nil, fmt.Errorf("backup: list tables: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("backup: scan table: %w", err)
		}
		out[name] = true
	}
	return out, rows.Err()
}

// hasColumn reports whether table has the named column.
func hasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)`,
		table, column).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("backup: inspect columns: %w", err)
	}
	return exists, nil
}

// countRows returns the row count of a table (the table name is validated
// against the queried base-table list before it is interpolated).
func countRows(ctx context.Context, db *sql.DB, table string) (int64, error) {
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM "`+table+`"`).Scan(&n); err != nil {
		return 0, fmt.Errorf("backup: count %s: %w", table, err)
	}
	return n, nil
}

// sampleHash hashes the first sampleHashLimit rows of a table ordered by id.
// The deterministic text rendering (row_to_json) is compared across the two
// instances, so any content drift in the sampled rows is caught.
func sampleHash(ctx context.Context, db *sql.DB, table string) (string, error) {
	query := fmt.Sprintf( // #nosec G201 -- table is validated against the introspected base-table list; the limit is a constant.
		`SELECT coalesce(md5(string_agg(md5(row_to_json(t)::text), '' ORDER BY t.id::text)), '')
		 FROM (SELECT * FROM "%s" ORDER BY id LIMIT %d) t`, table, sampleHashLimit)
	var h string
	if err := db.QueryRowContext(ctx, query).Scan(&h); err != nil {
		return "", fmt.Errorf("backup: sample hash %s: %w", table, err)
	}
	return h, nil
}

// verifyOpenSignals asserts the open-signal set (closed_at IS NULL) is intact:
// the count and the id set must match the restored instance.
func verifyOpenSignals(ctx context.Context, src, tgt *sql.DB, rep *Report) error {
	hasClosedAt, err := hasColumn(ctx, src, "risk_signals", "closed_at")
	if err != nil {
		return err
	}
	if !hasClosedAt {
		return nil
	}
	srcCount, srcIDs, err := openSignals(ctx, src)
	if err != nil {
		return err
	}
	tgtCount, tgtIDs, err := openSignals(ctx, tgt)
	if err != nil {
		return err
	}
	rep.OpenSignals = srcCount
	if srcCount != tgtCount || srcIDs != tgtIDs {
		rep.Mismatches = append(rep.Mismatches,
			fmt.Sprintf("open signals: source=%d restored=%d (id set %s)", srcCount, tgtCount, sameOrDiff(srcIDs, tgtIDs)))
	}
	return nil
}

// openSignals returns the count and the ordered-id hash of the open signals.
func openSignals(ctx context.Context, db *sql.DB) (int64, string, error) {
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM risk_signals WHERE closed_at IS NULL`).Scan(&n); err != nil {
		return 0, "", fmt.Errorf("backup: count open signals: %w", err)
	}
	var hash string
	err := db.QueryRowContext(ctx,
		`SELECT coalesce(md5(string_agg(id::text, ',' ORDER BY id)), '') FROM risk_signals WHERE closed_at IS NULL`).Scan(&hash)
	if err != nil {
		return 0, "", fmt.Errorf("backup: hash open signals: %w", err)
	}
	return n, hash, nil
}

// verifyAuditChain asserts the audit trail is intact: the row count matches and,
// when a hash chain is populated (row_hash not NULL), the chain links are
// consistent end-to-end (each row's prev_hash is the previous row's row_hash).
func verifyAuditChain(ctx context.Context, src, tgt *sql.DB, rep *Report) error {
	srcCount, err := countRows(ctx, src, "audit_events")
	if err != nil {
		return err
	}
	tgtCount, err := countRows(ctx, tgt, "audit_events")
	if err != nil {
		return err
	}
	rep.AuditRows = srcCount
	if srcCount != tgtCount {
		rep.Mismatches = append(rep.Mismatches,
			fmt.Sprintf("audit chain: source=%d restored=%d", srcCount, tgtCount))
	}

	hasHash, err := hasColumn(ctx, src, "audit_events", "row_hash")
	if err != nil {
		return err
	}
	if !hasHash {
		return nil
	}
	links, err := chainLinks(ctx, tgt)
	if err != nil {
		return err
	}
	chainPresent, chainOK, msg := verifyLinks(links)
	if !chainPresent {
		// The chain is disabled (all row_hash NULL): the row count above is the
		// integrity assertion (ARCH-007 §7 control 3b is optional).
		return nil
	}
	rep.ChainVerified = chainOK
	if !chainOK {
		rep.Mismatches = append(rep.Mismatches, "audit chain: "+msg)
	}
	return nil
}

type chainLink struct {
	prev string
	hash string
}

// chainLinks reads the audit rows in the chain order (occurred_at then id).
func chainLinks(ctx context.Context, db *sql.DB) ([]chainLink, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT coalesce(prev_hash, ''), coalesce(row_hash, '') FROM audit_events ORDER BY occurred_at, id`)
	if err != nil {
		return nil, fmt.Errorf("backup: read audit chain: %w", err)
	}
	defer rows.Close()
	var out []chainLink
	for rows.Next() {
		var l chainLink
		if err := rows.Scan(&l.prev, &l.hash); err != nil {
			return nil, fmt.Errorf("backup: scan audit chain: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// verifyLinks checks the structural chain: present when any row_hash is set;
// OK when every set row's prev_hash equals the preceding row's row_hash and no
// row_hash repeats.
func verifyLinks(links []chainLink) (present, ok bool, msg string) {
	seen := map[string]bool{}
	prev := ""
	for _, l := range links {
		if l.hash == "" {
			continue
		}
		present = true
		if l.prev != prev {
			return true, false, "prev_hash does not match the preceding row_hash"
		}
		if seen[l.hash] {
			return true, false, "duplicate row_hash in the chain"
		}
		seen[l.hash] = true
		prev = l.hash
	}
	return present, true, ""
}

// sameOrDiff renders an equality verdict for a message.
func sameOrDiff(a, b string) string {
	if a == b {
		return "same"
	}
	return "different"
}
