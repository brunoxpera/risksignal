package repo

// The optional audit hash chain (ARCH-007 §7 control 3b, WP-6.10 / DEV-123):
// the row-hash computation shared by AuditRepo.Append (stamping) and
// AuditRepo.VerifyChain (verification), plus the end-to-end verifier.
//
// The chain is order (occurred_at, id) — the audit trail's stable order.
// Each chained row stores prev_hash (the row_hash of its predecessor, NULL for
// the first chained row) and row_hash = SHA-256(prev_hash ‖ canonical row
// bytes). "Canonical row bytes" is a length-prefixed concatenation of the
// row's immutable content columns (the database-assigned id is deliberately
// excluded: it is not known before the insert, and every content column is
// covered), with the timestamps rendered in UTC microseconds and the before/
// after jsonb snapshots re-marshalled canonically so the value inserted and
// the value read back hash identically.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// auditChainLockKey is the transaction-scoped advisory lock that serialises
// concurrent chained appends (stampChain), so two transactions cannot both
// read the same LatestAuditHash and fork the chain. The value is arbitrary but
// stable ("RSIGAUDT" in ASCII); it is taken only when the chain is enabled.
const auditChainLockKey int64 = 0x5253494741554454

// auditChainRow is the immutable content of one audit row covered by the
// chain. It mirrors the insert params (not the database id).
type auditChainRow struct {
	AggregateType    string
	AggregateID      string
	ActorType        string
	ActorID          string
	ActorDisplayName string
	Action           string
	OccurredAt       time.Time
	Before           []byte
	After            []byte
	CorrelationID    string
}

// auditRowHash returns the hex SHA-256 of prev_hash ‖ canonical row bytes.
func auditRowHash(prevHash string, row auditChainRow) string {
	sum := sha256.Sum256(canonicalAuditRow(prevHash, row))
	return hex.EncodeToString(sum[:])
}

// canonicalAuditRow renders the length-prefixed canonical byte string hashed
// for one row. Every field is length-prefixed (len ":" bytes) so no field
// content can be confused with a separator.
func canonicalAuditRow(prevHash string, row auditChainRow) []byte {
	var b bytes.Buffer
	writeChainField(&b, prevHash)
	writeChainField(&b, row.AggregateType)
	writeChainField(&b, row.AggregateID)
	writeChainField(&b, row.ActorType)
	writeChainField(&b, row.ActorID)
	writeChainField(&b, row.ActorDisplayName)
	writeChainField(&b, row.Action)
	writeChainField(&b, row.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
	writeChainField(&b, string(canonicalJSON(row.Before)))
	writeChainField(&b, string(canonicalJSON(row.After)))
	writeChainField(&b, row.CorrelationID)
	return b.Bytes()
}

// writeChainField writes "<len>:<bytes>" — an unambiguous, self-delimiting
// field encoding.
func writeChainField(b *bytes.Buffer, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
}

// canonicalJSON normalises a jsonb value to a stable byte form: object keys
// sorted (encoding/json), no insignificant whitespace, numbers preserved as
// written (UseNumber). An empty value stays empty (NULL); a value that is not
// valid JSON falls back to the raw bytes so the hash is at least
// deterministic.
func canonicalJSON(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

// ChainStatus reports one end-to-end chain verification.
type ChainStatus struct {
	// Rows is the number of audit rows inspected.
	Rows int
	// Chained is the number of rows that carry a row_hash (verified).
	Chained int
	// Unchained is the number of rows without a row_hash — the pre-chain
	// prefix (the chain was enabled after they were written).
	Unchained int
	// FirstChainedAt / LastChainedAt bound the verified chain in occurred_at.
	FirstChainedAt time.Time
	LastChainedAt  time.Time
}

// ChainMismatchError reports the first row whose chain verification failed.
type ChainMismatchError struct {
	// RowID is the id of the offending audit row.
	RowID string
	// Position is its zero-based index in the chain order.
	Position int
	// Reason describes the failure ("row_hash does not match the recomputed
	// value" / "prev_hash does not link to the previous row_hash" / "row has
	// no row_hash after the chain started").
	Reason string
}

func (e *ChainMismatchError) Error() string {
	return fmt.Sprintf("audit chain verification failed at row %s (position %d): %s", e.RowID, e.Position, e.Reason)
}

// VerifyChain walks the whole audit trail in chain order, recomputing every
// chained row's SHA-256(prev_hash ‖ canonical row bytes) and checking that
// each row links to its predecessor. It returns a ChainStatus and nil when the
// chain is intact (an all-unchained trail — the chain never enabled — is
// intact with Chained 0), or a *ChainMismatchError at the first divergence
// (ARCH-007 §7 control 3b, §4 AT-015).
//
// It proves internal consistency — a row edited or removed after the chain
// started breaks the links. Anchoring the chain against wholesale removal of
// its head needs an external reference (the encrypted off-host backup, §4).
func (r *AuditRepo) VerifyChain(ctx context.Context) (ChainStatus, error) {
	const op = "audit.verify_chain"

	rows, err := r.q.ListAuditHashChain(ctx)
	if err != nil {
		return ChainStatus{}, mapDBError(op, err)
	}

	var st ChainStatus
	started := false
	prev := ""
	for i, row := range rows {
		st.Rows++
		if !row.RowHash.Valid {
			if started {
				return st, &ChainMismatchError{
					RowID:    uuidString(row.ID),
					Position: i,
					Reason:   "row has no row_hash after the chain started",
				}
			}
			st.Unchained++
			continue
		}

		chained := auditChainRow{
			AggregateType:    row.AggregateType,
			AggregateID:      uuidString(row.AggregateID),
			ActorType:        row.ActorType,
			ActorID:          row.ActorID,
			ActorDisplayName: textValue(row.ActorDisplayName),
			Action:           row.Action,
			OccurredAt:       tsTime(row.OccurredAt),
			Before:           row.Before,
			After:            row.After,
			CorrelationID:    row.CorrelationID,
		}

		if !started {
			// The first chained row anchors the chain; its recorded
			// prev_hash is the (NULL) link it was written with.
			started = true
			prev = textValue(row.PrevHash)
		} else if textValue(row.PrevHash) != prev {
			return st, &ChainMismatchError{
				RowID:    uuidString(row.ID),
				Position: i,
				Reason:   "prev_hash does not link to the previous row_hash",
			}
		}

		if got, want := row.RowHash.String, auditRowHash(prev, chained); got != want {
			return st, &ChainMismatchError{
				RowID:    uuidString(row.ID),
				Position: i,
				Reason:   "row_hash does not match the recomputed value",
			}
		}

		prev = row.RowHash.String
		st.Chained++
		at := tsTime(row.OccurredAt)
		if st.FirstChainedAt.IsZero() {
			st.FirstChainedAt = at
		}
		st.LastChainedAt = at
	}
	return st, nil
}
