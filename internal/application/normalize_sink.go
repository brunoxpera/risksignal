package application

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xpera/risksignal/internal/domain"
)

// normalizeSink is the persistence half of a normalise pass (ARCH-002 §1,
// §6): it implements NormalizeSink on the transaction of the pass, mapping
// the streamed domain objects onto the idempotent persistence writes of the
// I2 run — the vulnerability upsert by natural key (UQ cve_id), the
// immutable evidence inserts (UQ (raw_record_id, type, value_hash)) and the
// isolation of every RecordError into quarantine (ch. 8.6) — all in the
// same transaction as the run's terminal commit. It is the injectable fault
// seam of ARCH-002 §6: a failing write aborts the whole pass transaction,
// so the run and the cursor roll back with nothing partially committed.
//
// Attribution contract (for the adapters of WP-2.05+): the sink is bound to
// one raw record (the pass's NormalizeInput.RawRecordID); the adapter emits
// each record's Vulnerability before its Evidences, and the sink resolves
// the vulnerability of an evidence by the cve_id its canonical value
// carries, against the vulnerabilities this pass upserted. A record that
// fails to parse or normalise is isolated through RecordError — never
// emitted as an empty Vulnerability or an unattributable Evidence: those
// are adapter contract violations and abort the pass as infrastructure
// errors (ch. 5.2).
//
// The sink stamps every timestamp with the pass's clock instant (ch. 7.2):
// published_at/modified_at of the upsert and the quarantine timestamps come
// from the injected clock, never the database wall clock.
type normalizeSink struct {
	service     *Service
	tx          Tx
	sourceID    string // quarantine attribution
	runID       string // quarantine attribution; "" outside a run (reprocess)
	rawRecordID string // evidence + quarantine attribution

	now time.Time

	// vulnIDs maps every cve_id this pass upserted to its database id;
	// vulnOrder keeps the first-emission order for the reprocess link.
	vulnIDs   map[string]string
	vulnOrder []string
}

// newNormalizeSink binds one pass's sink to its transaction and
// attributions.
func newNormalizeSink(service *Service, tx Tx, sourceID, runID, rawRecordID string, now time.Time) *normalizeSink {
	return &normalizeSink{
		service:     service,
		tx:          tx,
		sourceID:    sourceID,
		runID:       runID,
		rawRecordID: rawRecordID,
		now:         now,
		vulnIDs:     make(map[string]string),
	}
}

// Vulnerability implements NormalizeSink: upsert the normalised
// vulnerability by its natural key cve_id (UQ cve_id — repeated ingestion
// of the same CVE refreshes the same row) and remember the returned id for
// the evidence attributions of the same record.
func (s *normalizeSink) Vulnerability(ctx context.Context, v domain.Vulnerability) error {
	if v.CVEID == "" {
		return InfraError("normalize_sink", fmt.Errorf("adapter emitted a vulnerability without cve_id; the record must be isolated via RecordError instead"))
	}
	id, err := s.service.vulns.Upsert(ctx, s.tx, VulnerabilityRecord{
		CVEID:       v.CVEID,
		Summary:     v.Summary,
		Description: v.Description,
		CVSS:        v.CVSS,
		References:  v.References,
		CPECfg:      v.CPECfg,
	}, s.now, s.now)
	if err != nil {
		return err
	}
	if _, seen := s.vulnIDs[v.CVEID]; !seen {
		s.vulnOrder = append(s.vulnOrder, v.CVEID)
	}
	s.vulnIDs[v.CVEID] = id
	return nil
}

// Evidence implements NormalizeSink: persist one immutable, typed source
// statement. The vulnerability is resolved by the cve_id of the evidence's
// canonical value against the pass's upserts (the adapter emits the
// record's Vulnerability first); the raw record attribution is the pass's
// own raw record; the value hash is the canonical SHA-256 of the marshalled
// value — the natural key (raw_record_id, type, value_hash) makes a
// repeated statement a no-op.
func (s *normalizeSink) Evidence(ctx context.Context, e domain.Evidence) error {
	if !e.Type.Valid() {
		return InfraError("normalize_sink", fmt.Errorf("adapter emitted an evidence of unknown type %q", e.Type))
	}
	if e.Value == nil {
		return InfraError("normalize_sink", fmt.Errorf("adapter emitted an evidence without a value"))
	}
	value, hash, err := evidenceValue(e.Value)
	if err != nil {
		return InfraError("normalize_sink", err)
	}
	var probe struct {
		CveID string `json:"cve_id"`
	}
	if err := json.Unmarshal(value, &probe); err != nil {
		return InfraError("normalize_sink", err)
	}
	vulnID, ok := s.vulnIDs[probe.CveID]
	if !ok {
		return InfraError("normalize_sink", fmt.Errorf("evidence for cve_id %q of a vulnerability this pass did not upsert; the adapter must emit the record's Vulnerability first", probe.CveID))
	}
	return s.service.vulns.AddEvidence(ctx, s.tx, EvidenceRecord{
		VulnerabilityID: vulnID,
		RawRecordID:     s.rawRecordID,
		Type:            e.Type,
		Value:           value,
		ValueHash:       hash,
	}, s.now)
}

// RecordError implements NormalizeSink: isolate one failed record into
// quarantine (ch. 8.6 "new") — the row is positioned, attributed (source,
// run, raw record) and re-addressable (payload hash) — in the same
// transaction as the run counters: the isolation never aborts the run, an
// isolated error is counted, not fatal (ch. 8.1 step 5).
func (s *normalizeSink) RecordError(ctx context.Context, e RecordError) error {
	if e.Position == "" || e.Reason == "" || e.PayloadHash == "" {
		return InfraError("normalize_sink", fmt.Errorf("adapter emitted an incomplete RecordError (position %q, reason %q, payload hash %q)", e.Position, e.Reason, e.PayloadHash))
	}
	_, err := s.service.quarantine.Insert(ctx, s.tx, s.sourceID, s.runID, s.rawRecordID, e.Position, e.Reason, e.PayloadHash, s.now)
	return err
}

// singleVulnID returns the vulnerability id of the pass when exactly one
// distinct vulnerability was upserted, "" otherwise — the reprocess
// resolution link of a single-record pass (ARCH-002 §4).
func (s *normalizeSink) singleVulnID() string {
	if len(s.vulnOrder) == 1 {
		return s.vulnIDs[s.vulnOrder[0]]
	}
	return ""
}

// compile-time check that the sink satisfies the seam the adapters stream
// into.
var _ NormalizeSink = (*normalizeSink)(nil)
