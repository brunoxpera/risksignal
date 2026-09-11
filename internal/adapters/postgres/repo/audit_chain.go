package repo

// The optional audit hash chain (ARCH-007 §7 control 3b, WP-6.10 / DEV-123):
// the row-hash computation shared by AuditRepo.Append (stamping) and
// AuditRepo.VerifyChain (verification), plus the end-to-end verifier.
//
// Each chained row stores prev_hash (the row_hash of its predecessor, NULL for
// the chain head) and row_hash = SHA-256(prev_hash ‖ canonical row bytes). The
// chain's order is defined by these prev_hash links — the order the rows were
// stamped in — and NOT by (occurred_at, id): under concurrent writers, a clock
// skew, or an occurred_at tie broken by a random id, a row can be appended with
// an occurred_at that sorts before its predecessor's, so a walk in
// (occurred_at, id) order can reach a successor before the predecessor it
// links to. VerifyChain therefore follows the prev_hash links it finds instead
// of re-sorting the trail. "Canonical row bytes" is a length-prefixed
// concatenation of the row's immutable content columns (the database-assigned
// id is deliberately excluded: it is not known before the insert, and every
// content column is covered), with the timestamps rendered in UTC microseconds
// and the before/after jsonb snapshots re-marshalled canonically so the value
// inserted and the value read back hash identically.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
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
// sorted (encoding/json), no insignificant whitespace, and every number
// rendered in the canonical decimal form jsonb's numeric type stores and
// prints (normaliseJSONNumber). An empty value stays empty (NULL); a value that
// is not valid JSON falls back to the raw bytes so the hash is at least
// deterministic.
//
// The numeric normalisation is what makes the stamp-time and verify-time byte
// strings agree: stamping hashes the raw input lexeme, but the before/after
// columns are jsonb, and PostgreSQL canonicalises their numbers on the way in
// (1e2 becomes 100). Without this step a snapshot holding an exponent-form or
// extreme-magnitude number hashed differently at stamp time than when read back,
// so an untampered chain reported a false mismatch.
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
	out, err := json.Marshal(normaliseJSONNumbers(v))
	if err != nil {
		return raw
	}
	return out
}

// normaliseJSONNumbers walks a decoded JSON value and rewrites every number to
// its canonical decimal form (normaliseJSONNumber); objects, arrays and the
// non-number scalars pass through unchanged.
func normaliseJSONNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		return normaliseJSONNumber(t)
	case []any:
		for i := range t {
			t[i] = normaliseJSONNumbers(t[i])
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = normaliseJSONNumbers(t[k])
		}
		return t
	default:
		return v
	}
}

// normaliseJSONNumber renders a JSON number in the canonical decimal form
// PostgreSQL's jsonb (the numeric type) stores and prints: no exponent, no
// leading zeros, no sign on zero, and the input's scale preserved (a trailing
// fractional zero is kept; a positive exponent's implied zeros are made
// explicit). It mirrors numeric_in's scale rule — digits after the point minus
// the exponent, clamped at zero — and numeric_out's plain-decimal rendering,
// so a value that round-trips through a jsonb column hashes identically before
// and after the round trip.
func normaliseJSONNumber(n json.Number) json.Number {
	s := n.String()
	neg := false
	if len(s) > 0 && (s[0] == '-' || s[0] == '+') {
		neg = s[0] == '-'
		s = s[1:]
	}
	exp := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		if e, err := strconv.Atoi(s[i+1:]); err == nil {
			exp = e
		}
		s = s[:i]
	}
	intPart, fracPart := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, fracPart = s[:i], s[i+1:]
	}
	digits := intPart + fracPart
	scale := len(fracPart) - exp
	if scale < 0 {
		digits += strings.Repeat("0", -scale)
		scale = 0
	}
	var out string
	if scale == 0 {
		out = strings.TrimLeft(digits, "0")
		if out == "" {
			out = "0"
		}
	} else {
		if len(digits) < scale {
			digits = strings.Repeat("0", scale-len(digits)) + digits
		}
		whole := strings.TrimLeft(digits[:len(digits)-scale], "0")
		if whole == "" {
			whole = "0"
		}
		out = whole + "." + digits[len(digits)-scale:]
	}
	if neg && strings.Trim(out, "0.") != "" {
		out = "-" + out
	}
	return json.Number(out)
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
	// value" / "prev_hash does not link to the previous row_hash" / "chain has
	// no head" / "chain is forked" / "chained row is unreachable from the
	// chain head").
	Reason string
}

func (e *ChainMismatchError) Error() string {
	return fmt.Sprintf("audit chain verification failed at row %s (position %d): %s", e.RowID, e.Position, e.Reason)
}

// VerifyChain walks the chain's prev_hash links end-to-end, recomputing every
// chained row's SHA-256(prev_hash ‖ canonical row bytes) and checking that each
// row matches its stored hash and links to its predecessor. It returns a
// ChainStatus and nil when the chain is intact (an all-unchained trail — the
// chain never enabled — is intact with Chained 0), or a *ChainMismatchError at
// the first divergence (ARCH-007 §7 control 3b, §4 AT-015).
//
// It walks the links, not the (occurred_at, id) row order, because that order
// is not the append order the stamps were written in (concurrent writers, a
// clock skew, or an occurred_at tie broken by a random id can append a row
// whose occurred_at sorts before its predecessor's). It builds the row_hash →
// row index over the chained rows, starts at the single head (the chained row
// with a NULL prev_hash) and follows each row_hash → the row whose prev_hash is
// that hash, so a successor is never visited before the predecessor it links
// to. A missing head, a fork (two rows link to NULL, two rows share a
// row_hash, or one predecessor has two successors), a dangling prev_hash, and a
// chained row the walk never reaches are all reported as failures.
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
	st.Rows = len(rows)

	// Partition the trail into the chained rows (row_hash present) and the
	// unchained prefix (row_hash NULL — written before the chain started). The
	// (occurred_at, id) order ListAuditHashChain returns is deliberately not
	// relied on; the chained rows are ordered by their links below. The
	// occurred_at bounds look across every chained row, so they do not depend
	// on the walk order either.
	chained := make([]gen.AuditEvent, 0, len(rows))
	for _, row := range rows {
		if !row.RowHash.Valid {
			st.Unchained++
			continue
		}
		chained = append(chained, row)
		at := tsTime(row.OccurredAt)
		if st.FirstChainedAt.IsZero() || at.Before(st.FirstChainedAt) {
			st.FirstChainedAt = at
		}
		if at.After(st.LastChainedAt) {
			st.LastChainedAt = at
		}
	}
	if len(chained) == 0 {
		return st, nil // all-unchained trail (the chain never started): intact
	}

	// Index the chained rows by their own row_hash (the key a successor links
	// through; a duplicate is a fork) and by the prev_hash each one links to
	// (the edge the walk follows).
	byRowHash := make(map[string]int, len(chained))
	byPrev := make(map[string][]int, len(chained))
	for i, row := range chained {
		if _, dup := byRowHash[row.RowHash.String]; dup {
			return st, chainMismatch(row, 0, "chain is forked: two rows share a row_hash")
		}
		byRowHash[row.RowHash.String] = i
		prev := textValue(row.PrevHash)
		byPrev[prev] = append(byPrev[prev], i)
	}

	// Every non-NULL prev_hash must link to a chained row: a prev_hash with no
	// matching row_hash is a dangling link — a removed or rewritten predecessor,
	// including a removed head (wholesale head removal is otherwise undetectable
	// without the external anchor, §4).
	for _, row := range chained {
		if !row.PrevHash.Valid {
			continue
		}
		if _, ok := byRowHash[row.PrevHash.String]; !ok {
			return st, chainMismatch(row, 0, "prev_hash does not link to the previous row_hash")
		}
	}

	// The chain starts at its single head — the one chained row whose prev_hash
	// is NULL. No head (a cycle or a rewritten head) or more than one (a fork at
	// the start) is a chain failure.
	head := -1
	for i := range chained {
		if chained[i].PrevHash.Valid {
			continue
		}
		if head != -1 {
			return st, chainMismatch(chained[i], 0, "chain is forked: more than one row links to NULL")
		}
		head = i
	}
	if head == -1 {
		return st, chainMismatch(chained[0], 0, "chain has no head: no chained row links to NULL")
	}

	// Walk the links from the head, recomputing each row's hash and checking it
	// matches the stored one, then following row_hash → the row whose prev_hash
	// is that hash. The walk must visit every chained row exactly once: a
	// revisited row is a loop, a row with two successors is a fork, and a chained
	// row the walk never reaches is unreachable (a fork or a gap).
	visited := make([]bool, len(chained))
	cur, pos := head, 0
	for cur != -1 {
		if visited[cur] {
			return st, chainMismatch(chained[cur], pos, "chain is forked or loops: a row is reached twice")
		}
		visited[cur] = true
		row := chained[cur]
		if got, want := auditRowHash(textValue(row.PrevHash), chainRowOf(row)), row.RowHash.String; got != want {
			return st, chainMismatch(row, pos, "row_hash does not match the recomputed value")
		}
		st.Chained++
		succ := byPrev[row.RowHash.String]
		if len(succ) > 1 {
			return st, chainMismatch(row, pos, "chain is forked: two rows link to the same predecessor")
		}
		if len(succ) == 0 {
			break
		}
		cur, pos = succ[0], pos+1
	}
	for i := range chained {
		if !visited[i] {
			return st, chainMismatch(chained[i], pos, "chained row is unreachable from the chain head")
		}
	}
	return st, nil
}

// chainRowOf maps a stored audit row onto the immutable content the chain
// hashes (it mirrors the insert params, not the database id).
func chainRowOf(row gen.AuditEvent) auditChainRow {
	return auditChainRow{
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
}

// chainMismatch builds the typed verification failure for one row.
func chainMismatch(row gen.AuditEvent, position int, reason string) *ChainMismatchError {
	return &ChainMismatchError{RowID: uuidString(row.ID), Position: position, Reason: reason}
}
