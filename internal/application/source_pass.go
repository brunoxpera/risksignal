package application

import (
	"context"
	"time"
)

// sourcePassInput assembles the adapter input of one normalise pass and
// wires the deferred full-set specialisation of the EPSS path at the
// use-case boundary (DEV-041, ARCH-002 §1/§2.3): the EPSS pass (adapter
// type "epss") receives the BulkRowWriter over the pass transaction, and
// the returned finish runs its TRUNCATE + COPY load after the adapter's
// Normalize succeeded — so the daily-set swap commits atomically with the
// run (ADR-013). Every other source type reads no bulk field (nil-safe)
// and finish is a no-op for them; the KEV previous-set read (removal
// historisation, ARCH-002 §2.2) wires through the same helper.
//
// The pass's identity fields (raw record id, payload, content hash, fetch
// metadata) are carried as given — the caller resolved the stored record
// or the fetch output.
func (s *Service) sourcePassInput(
	ctx context.Context,
	tx Tx,
	adapterType SourceType,
	sourceID, rawRecordID, externalID string,
	fetchedAt time.Time,
	payload []byte,
	contentHash string,
	meta FetchMeta,
	now time.Time,
) (input NormalizeInput, finish func(context.Context) error, err error) {
	input = NormalizeInput{
		RawRecordID: rawRecordID,
		Payload:     payload,
		ContentHash: contentHash,
		Meta:        meta,
	}

	var bulk *epssBulkWriter
	switch adapterType {
	case SourceTypeEPSS:
		// The bulk writer is bound to the pass transaction: TRUNCATE +
		// COPY run on it and commit with the run (the atomic swap of the
		// current daily set, ARCH-002 §2.3/ADR-013). model_version is the
		// daily file's date, loaded_at the pass's clock instant.
		bulk = newEpssBulkWriter(tx, epssModelVersionOf(externalID, fetchedAt), now)
		input.EpssBulk = bulk
	}

	finish = func(ctx context.Context) error {
		if bulk == nil {
			return nil // no bulk specialisation: nothing to load
		}
		if _, err := bulk.load(ctx); err != nil {
			return err
		}
		return nil
	}
	return input, finish, nil
}
