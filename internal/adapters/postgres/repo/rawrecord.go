package repo

import (
	"context"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
)

// RawRecordRepo is the postgres implementation of application.RawRecordRepo
// (raw_records.sql): the idempotent storage of the unchanged raw source
// document (bytea payload + self-describing content_encoding from migration
// 00004, ADR-013/ARCH-002 §3) and the by-id read the normalise and
// quarantine-reprocess paths start from (ARCH-002 §4).
type RawRecordRepo struct {
	q *gen.Queries
}

// NewRawRecordRepo binds the repository to one query set.
func NewRawRecordRepo(q *gen.Queries) *RawRecordRepo { return &RawRecordRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.RawRecordRepo = (*RawRecordRepo)(nil)

// Insert implements application.RawRecordRepo: store the unchanged document
// and return the row id — newly inserted, or the already existing one of an
// identical earlier ingest (ON CONFLICT DO NOTHING on the natural key
// (source_id, external_id, content_hash)). contentEncoding describes the
// payload bytes ('identity' | 'gzip' | 'json'); "" stores NULL.
func (r *RawRecordRepo) Insert(ctx context.Context, tx application.Tx, sourceID, externalID string, payload []byte, contentHash, contentEncoding string, fetchedAt time.Time) (string, error) {
	const op = "raw_record.insert"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return "", application.ValidationError(op, err)
	}
	id, err := r.q.WithTx(tx).InsertRawRecord(ctx, gen.InsertRawRecordParams{
		SourceID:        srcID,
		ExternalID:      externalID,
		ContentHash:     contentHash,
		Payload:         payload,
		ContentEncoding: toTextOpt(contentEncoding),
		FetchedAt:       toTS(fetchedAt),
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(id), nil
}

// GetByID implements application.RawRecordRepo: return the stored document
// with its payload bytes. A missing record is a not-found Error.
func (r *RawRecordRepo) GetByID(ctx context.Context, id string) (application.RawRecord, error) {
	const op = "raw_record.get_by_id"

	recID, err := toUUID(id)
	if err != nil {
		return application.RawRecord{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetRawRecordByID(ctx, recID)
	if err != nil {
		return application.RawRecord{}, mapDBError(op, err)
	}
	return application.RawRecord{
		ID:              uuidString(row.ID),
		SourceID:        uuidString(row.SourceID),
		ExternalID:      row.ExternalID,
		ContentHash:     row.ContentHash,
		Payload:         row.Payload,
		ContentEncoding: row.ContentEncoding.String, // NULL → ""
		FetchedAt:       row.FetchedAt.Time,
	}, nil
}

// PreviousKEVCVEs implements application.RawRecordRepo: read the CVE ids
// of the source's previously stored KEV catalog — the kev evidences of the
// latest stored raw record other than the pass's own (ListPreviousKEVCVEs,
// sorted, deduplicated). A source without a prior raw record yields nil.
func (r *RawRecordRepo) PreviousKEVCVEs(ctx context.Context, sourceID, excludeRawRecordID string) ([]string, error) {
	const op = "raw_record.previous_kev_cves"

	srcID, err := toUUID(sourceID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	exID, err := toUUID(excludeRawRecordID)
	if err != nil {
		return nil, application.ValidationError(op, err)
	}
	cves, err := r.q.ListPreviousKEVCVEs(ctx, gen.ListPreviousKEVCVEsParams{
		SourceID:           srcID,
		ExcludeRawRecordID: exID,
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	return cves, nil
}
