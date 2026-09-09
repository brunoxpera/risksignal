package application

import (
	"context"
	"time"
)

// sourcePassInput assembles the adapter input of one normalise pass and
// wires the deferred full-set specialisations at the use-case boundary
// (DEV-041, ARCH-002 §1/§2.2/§2.3): the two additive, nil-safe
// NormalizeInput fields the WP-2.06/2.07 adapters read.
//
// The EPSS pass (adapter type "epss") receives the BulkRowWriter over the
// pass transaction, and the returned finish runs its TRUNCATE + COPY load
// after the adapter's Normalize succeeded — so the daily-set swap commits
// atomically with the run (ADR-013). The KEV pass (adapter type "kev")
// receives the CVE ids of the source's previously stored catalog, which
// activates removal historisation (kev_removed evidence, ch. 8.3).
// NVD/synthetic passes never read the fields and keep them nil, and finish
// is a no-op for every non-EPSS type.
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
	case SourceTypeKEV:
		// The previous catalog's CVE set activates removal historisation
		// (ch. 8.3, ARCH-002 §2.2): the KEV adapter emits a kev_removed
		// evidence for every CVE of the previously stored catalog that the
		// new one no longer carries. The read excludes the pass's own raw
		// record — its evidence rows would be the new catalog's, never
		// the previous set's. A first import has no previous record and
		// the set stays nil (no removals).
		previous, err := s.raws.PreviousKEVCVEs(ctx, sourceID, rawRecordID)
		if err != nil {
			return NormalizeInput{}, nil, err
		}
		input.PreviousKEVCVEs = previous
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
