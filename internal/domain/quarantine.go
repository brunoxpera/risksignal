package domain

import "fmt"

// QuarantineStatus is the lifecycle state of a quarantined record
// (implementation concept ch. 8.6, ARCH-002 §4 quarantine.status; the
// schema CHECK allows exactly these four values).
//
//	new            — the record could not be processed; source, position,
//	                 reason and payload hash are shown to the operator.
//	acknowledged   — an operator reviewed the error; comment and
//	                 responsibility are recorded.
//	ready_for_retry — the adapter, rule or data was corrected; a targeted
//	                 reprocess with the current normaliser version may run.
//	resolved       — the record was processed successfully or deliberately
//	                 discarded; the result and the link to the new domain
//	                 object are documented.
type QuarantineStatus string

// Allowed QuarantineStatus values (ARCH-002 §3 CHECK, §4).
const (
	QuarantineStatusNew           QuarantineStatus = "new"
	QuarantineStatusAcknowledged  QuarantineStatus = "acknowledged"
	QuarantineStatusReadyForRetry QuarantineStatus = "ready_for_retry"
	QuarantineStatusResolved      QuarantineStatus = "resolved"
)

// Valid reports whether s is an allowed QuarantineStatus value.
func (s QuarantineStatus) Valid() bool {
	switch s {
	case QuarantineStatusNew,
		QuarantineStatusAcknowledged,
		QuarantineStatusReadyForRetry,
		QuarantineStatusResolved:
		return true
	}
	return false
}

// ParseQuarantineStatus parses s into a QuarantineStatus. Unknown values
// error.
func ParseQuarantineStatus(s string) (QuarantineStatus, error) {
	v := QuarantineStatus(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid QuarantineStatus %q", s)
	}
	return v, nil
}

// Quarantine is a record the normaliser isolated because it failed to
// parse/normalise (implementation concept ch. 8.6, ARCH-002 §3
// quarantine). The row is positioned (Position within the payload),
// attributed (SourceID, the run and raw record that carried it) and
// re-addressable (PayloadHash) so a reprocess can re-read exactly the
// offending slice.
//
// The aggregate is the state machine of ARCH-002 §4. The allowed
// transitions are exactly:
//
//	(create) ──────────────────────► new
//	new ── Acknowledge ────────────► acknowledged
//	new ── MarkReadyForRetry ──────► ready_for_retry
//	acknowledged ─ MarkReadyForRetry ► ready_for_retry
//	new ── ReprocessSucceeded ─────► resolved
//	ready_for_retry ─ ReprocessSucceeded ► resolved
//	new ── ReprocessFailed ────────► new (attempts++)
//	ready_for_retry ─ ReprocessFailed ► ready_for_retry (attempts++)
//
// resolved is terminal. Every other pair is invalid and not representable:
// each transition is a guarded method and Status changes nowhere else.
//
// Acknowledge carries the reviewer and the note; ReprocessSucceeded
// carries the link to the new domain object (or a justified-discard note).
// The timestamps of the table (acknowledged_at, resolved_at,
// created_at/updated_at) belong to the application layer behind the clock
// port, like on every other aggregate (package doc).
type Quarantine struct {
	ID          string // uuid
	SourceID    string // sources.id — the source the record came from
	SourceRunID string // source_runs.id — the run that isolated it; "" when not yet attributed
	RawRecordID string // raw_records.id — the raw document it came from; "" when not yet attributed
	Position    string // byte offset | line number | JSON pointer within the payload
	Reason      string // stable error_code + human message (ch. 5.2)
	PayloadHash string // SHA-256 hex of the offending record/slice

	Status   QuarantineStatus
	Attempts int // failed reprocess attempts, never reset

	// AcknowledgedBy/AcknowledgedNote are recorded by Acknowledge;
	// acknowledged_at is stamped by the application layer.
	AcknowledgedBy   string
	AcknowledgedNote string

	// ResolvedVulnerabilityID/ResolvedEvidenceID link the new domain
	// object a successful reprocess created; ResolvedNote documents the
	// resolution (or the justified discard). resolved_at is stamped by
	// the application layer.
	ResolvedVulnerabilityID string
	ResolvedEvidenceID      string
	ResolvedNote            string
}

// NewQuarantine isolates one failed record (ARCH-002 §4 "(create) → new"):
// the row starts with status new and zero attempts. id, sourceID, position,
// reason and payloadHash are required (the schema columns are NOT NULL);
// sourceRunID and rawRecordID are optional — a record can be isolated
// before the run/raw-record attribution exists.
func NewQuarantine(id, sourceID, sourceRunID, rawRecordID, position, reason, payloadHash string) (Quarantine, error) {
	if id == "" {
		return Quarantine{}, fmt.Errorf("domain: quarantine id must not be empty")
	}
	if sourceID == "" {
		return Quarantine{}, fmt.Errorf("domain: quarantine source_id must not be empty")
	}
	if position == "" {
		return Quarantine{}, fmt.Errorf("domain: quarantine position must not be empty")
	}
	if reason == "" {
		return Quarantine{}, fmt.Errorf("domain: quarantine reason must not be empty")
	}
	if payloadHash == "" {
		return Quarantine{}, fmt.Errorf("domain: quarantine payload_hash must not be empty")
	}
	return Quarantine{
		ID:          id,
		SourceID:    sourceID,
		SourceRunID: sourceRunID,
		RawRecordID: rawRecordID,
		Position:    position,
		Reason:      reason,
		PayloadHash: payloadHash,
		Status:      QuarantineStatusNew,
	}, nil
}

// Acknowledge records the operator review (new → acknowledged, ARCH-002
// §4): the reviewer and the note are recorded; the acknowledgement
// timestamp is stamped by the application layer. Only a new record can be
// acknowledged — reviewing twice, or reviewing a record that is already
// retryable or resolved, is not a transition of the machine.
func (q Quarantine) Acknowledge(acknowledgedBy, note string) (Quarantine, error) {
	if q.Status != QuarantineStatusNew {
		return Quarantine{}, fmt.Errorf("domain: quarantine acknowledge: a %s record cannot be acknowledged", q.Status)
	}
	if acknowledgedBy == "" {
		return Quarantine{}, fmt.Errorf("domain: quarantine acknowledge: acknowledged_by must not be empty")
	}
	q.Status = QuarantineStatusAcknowledged
	q.AcknowledgedBy = acknowledgedBy
	q.AcknowledgedNote = note
	return q, nil
}

// MarkReadyForRetry marks the record retryable once the adapter, rule or
// data was fixed (new|acknowledged → ready_for_retry, ARCH-002 §4) —
// bumping the adapter's normalizer_version is the mechanism behind this
// transition (§1). A record already ready, resolved or failed-over cannot
// be marked.
func (q Quarantine) MarkReadyForRetry() (Quarantine, error) {
	if q.Status != QuarantineStatusNew && q.Status != QuarantineStatusAcknowledged {
		return Quarantine{}, fmt.Errorf("domain: quarantine ready_for_retry: only a new or acknowledged record can be marked ready, got %s", q.Status)
	}
	q.Status = QuarantineStatusReadyForRetry
	return q, nil
}

// ReprocessSucceeded closes a reprocess that succeeded (new|ready_for_retry
// → resolved, ARCH-002 §4): the record is resolved and the result is
// documented — ResolvedVulnerabilityID/ResolvedEvidenceID link the new
// domain object the reprocess created, ResolvedNote documents the outcome
// (a justified discard carries no link but must state the reason; ch. 8.6
// "resolved"). resolved is terminal: no transition leaves it.
func (q Quarantine) ReprocessSucceeded(resolvedVulnerabilityID, resolvedEvidenceID, note string) (Quarantine, error) {
	if q.Status != QuarantineStatusNew && q.Status != QuarantineStatusReadyForRetry {
		return Quarantine{}, fmt.Errorf("domain: quarantine resolve: only a new or ready_for_retry record can resolve, got %s", q.Status)
	}
	if resolvedVulnerabilityID == "" && resolvedEvidenceID == "" && note == "" {
		return Quarantine{}, fmt.Errorf("domain: quarantine resolve: the resolution must link the new domain object or carry a note")
	}
	q.Status = QuarantineStatusResolved
	q.ResolvedVulnerabilityID = resolvedVulnerabilityID
	q.ResolvedEvidenceID = resolvedEvidenceID
	q.ResolvedNote = note
	return q, nil
}

// ReprocessFailed records a reprocess that still fails (ARCH-002 §4:
// "reprocess failed → attempts++, stays retryable"). The attempt counter
// increments and the record stays in its retryable state — ready_for_retry
// stays ready_for_retry, a reprocess attempted straight from new stays new
// (the table's "ready_for_retry / new" outcome row). A failed attempt
// never resolves or aborts the record.
func (q Quarantine) ReprocessFailed() (Quarantine, error) {
	if q.Status != QuarantineStatusNew && q.Status != QuarantineStatusReadyForRetry {
		return Quarantine{}, fmt.Errorf("domain: quarantine reprocess failed: only a new or ready_for_retry record can be retried, got %s", q.Status)
	}
	q.Attempts++
	return q, nil
}
