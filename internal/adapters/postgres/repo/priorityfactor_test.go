package repo

import (
	"context"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// This file unit-tests the EPSS source of the priority factor rebuild
// (DEV-078) without a database: a stub gen.DBTX answers the three reads
// Rebuild issues by SQL shape, so the test proves the factor percentile is
// read from epss_current (never from an `epss` evidence row) and that a CVE
// absent from the current set yields the no-factor default of 0.

// stubRow is a pgx.Row driven by one scan function.
type stubRow struct{ scan func(dest ...any) error }

func (r stubRow) Scan(dest ...any) error { return r.scan(dest...) }

// stubRows is a pgx.Rows over a list of per-row scan functions.
type stubRows struct {
	scans []func(dest ...any) error
	i     int
}

func (r *stubRows) Close()                                       {}
func (r *stubRows) Err() error                                   { return nil }
func (r *stubRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *stubRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (r *stubRows) Next() bool {
	if r.i >= len(r.scans) {
		return false
	}
	r.i++
	return true
}

func (r *stubRows) Scan(dest ...any) error { return r.scans[r.i-1](dest...) }
func (r *stubRows) Values() ([]any, error) { return nil, nil }
func (r *stubRows) RawValues() [][]byte    { return nil }
func (r *stubRows) Conn() *pgx.Conn        { return nil }
func (r *stubRows) TypeMap() *pgtype.Map   { return nil }

// stubDBTX is a gen.DBTX that answers Rebuild's reads by SQL shape. The
// unused Exec/CopyFrom are inert: the factor read port is read-only.
type stubDBTX struct {
	queryRow func(sql string, args ...any) pgx.Row
	query    func(sql string, args ...any) (pgx.Rows, error)
}

func (s stubDBTX) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (s stubDBTX) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	return s.query(sql, args...)
}
func (s stubDBTX) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	return s.queryRow(sql, args...)
}
func (s stubDBTX) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, nil
}

// factorStubDBTX wires the three rebuild reads: the signal's factor source
// (cve_id + asset context), the vulnerability's KEV/CVSS evidence — with no
// `epss` evidence row — and the epss_current lookup (absent when nil).
func factorStubDBTX(cveID string, epss *float64) gen.DBTX {
	var pct pgtype.Numeric
	if epss != nil {
		if err := pct.Scan(strconv.FormatFloat(*epss, 'f', -1, 64)); err != nil {
			panic(err)
		}
	}
	at := time.Unix(0, 0).UTC()
	return stubDBTX{
		queryRow: func(sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "FROM risk_signals"):
				return stubRow{scan: func(dest ...any) error {
					*(dest[0].(*pgtype.UUID)) = pgtype.UUID{Valid: true}
					*(dest[1].(*string)) = string(domain.MatchMethodExactIdentifier)
					*(dest[2].(*string)) = cveID
					*(dest[3].(*string)) = string(domain.CriticalityCritical)
					*(dest[4].(*string)) = string(domain.ExposureInternet)
					return nil
				}}
			case strings.Contains(sql, "FROM epss_current"):
				if epss == nil {
					return stubRow{scan: func(...any) error { return pgx.ErrNoRows }}
				}
				return stubRow{scan: func(dest ...any) error {
					*(dest[0].(*string)) = cveID
					*(dest[1].(*pgtype.Numeric)) = pct
					*(dest[2].(*pgtype.Numeric)) = pct
					*(dest[3].(*string)) = "2026-09-09"
					*(dest[4].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: at, Valid: true}
					return nil
				}}
			}
			return stubRow{scan: func(...any) error { return nil }}
		},
		query: func(sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "FROM evidences") {
				return &stubRows{scans: []func(dest ...any) error{scanCVSSEvidence, scanKEVEvidence}}, nil
			}
			return &stubRows{}, nil
		},
	}
}

func scanCVSSEvidence(dest ...any) error {
	*(dest[0].(*string)) = string(domain.EvidenceTypeCVSS)
	*(dest[1].(*[]byte)) = []byte(`{"cve_id":"CVE-2024-0001","base_score":5.0}`)
	*(dest[2].(*pgtype.Timestamptz)) = pgtype.Timestamptz{}
	return nil
}

func scanKEVEvidence(dest ...any) error {
	*(dest[0].(*string)) = string(domain.EvidenceTypeKEV)
	*(dest[1].(*[]byte)) = []byte(`{"cve_id":"CVE-2024-0001","known_exploited":false}`)
	*(dest[2].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: time.Unix(0, 0).UTC(), Valid: true}
	return nil
}

// TestRebuildReadsEpssFromCurrent verifies the DEV-078 fix: the rebuilt
// factors carry the percentile of the epss_current row, even though the
// vulnerability has no `epss` evidence row (KEV/CVSS still come from
// evidence). An empty current set yields the no-factor default of 0.
func TestRebuildReadsEpssFromCurrent(t *testing.T) {
	ctx := context.Background()
	const cveID = "CVE-2024-0001"

	epss := 0.97
	r := NewPriorityFactorRepo(gen.New(factorStubDBTX(cveID, &epss)))
	rebuild, err := r.Rebuild(ctx, "11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	f := rebuild.Factors
	if math.Abs(f.EPSS-0.97) > 1e-9 {
		t.Fatalf("factors.EPSS = %v, want 0.97 read from epss_current", f.EPSS)
	}
	if f.CVSS != 5.0 || f.KEV {
		t.Fatalf("factors = %+v, want CVSS 5.0 / KEV false from evidence", f)
	}
	if f.Confidence != domain.ConfidenceHigh || f.Method != domain.MatchMethodExactIdentifier {
		t.Fatalf("factors = %+v, want the exact_identifier/high method pair", f)
	}
	if rebuild.CVEID != cveID {
		t.Fatalf("rebuild.CVEID = %q, want %q", rebuild.CVEID, cveID)
	}

	// The CVE is absent from the current set: EPSS is the no-factor default,
	// not an error (a signal the day's file does not score).
	r2 := NewPriorityFactorRepo(gen.New(factorStubDBTX(cveID, nil)))
	rebuild2, err := r2.Rebuild(ctx, "22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatalf("Rebuild without epss_current row: %v", err)
	}
	if rebuild2.Factors.EPSS != 0 {
		t.Fatalf("factors.EPSS = %v, want 0 when the CVE is not in epss_current", rebuild2.Factors.EPSS)
	}
}
