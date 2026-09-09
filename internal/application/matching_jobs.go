package application

// Outbox vocabulary of the matching job types (ARCH-003 §5, ch. 14.1,
// ADR-012, WP-3.08): the event type discriminators, the job payload
// shapes and the dedupe key builders of matching.rebuild and
// matching.recompute — the job contract the enqueue side and the relay
// handlers share. The inventory commit of WP-3.05 (DEV-060) enqueues
// matching.rebuild jobs; the NVD incremental runs of WP-3.09 (DEV-052)
// enqueue pre-filtered matching.recompute batches; the WP-3.08 handlers
// in internal/adapters/worker consume both. This file is the single
// source of that contract, mirroring source_jobs.go for the source.run
// job types.
//
// Every payload carries identities and hashes only — CVE ids, rule
// versions, snapshot hashes, correlation ids and timestamps — never a
// secret (ch. 3.3, TR-013). The dedupe keys make the outbox UQ
// (dedupe_key) idempotent at the schema level for the whole job lifetime
// (ADR-012 point 4): re-enqueuing a job that is already queued — or was
// already delivered — is a conflict the enqueuers treat as a no-op, and a
// re-claimed job (crash, expired lease) re-runs against idempotent match
// inserts (UQ (vulnerability_id, component_id, rule_version)) with no
// double effect (TR-012).

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Event type discriminators of the matching jobs (ARCH-003 §5). The relay
// registry keys its handlers by these values; the enqueue side writes
// them into outbox.type.
const (
	// EventTypeMatchingRebuild is the outbox type of the matching.rebuild
	// job: exactly one per inventory state change (initial import, rule
	// change), enqueued by the inventory commit on the same transaction
	// as the state change (inventory_commit.go, DEV-060). The job walks
	// the inventory component set in bounded batches and computes the
	// matches of every component against its candidate CVEs
	// (inventory-driven, ADR-012 — no CVE-driven fan-out).
	EventTypeMatchingRebuild = "matching.rebuild"

	// EventTypeMatchingRecompute is the outbox type of the
	// matching.recompute job: one pre-filtered CVE batch (guide 500 ids)
	// enqueued when new evidence arrives for CVEs with inventory
	// relevance (WP-3.09/DEV-052 — the NVD incremental path; nothing in
	// the I3 code base enqueues it before that work package). The job
	// resolves the candidate components of every CVE of the batch through
	// the WP-3.07 pre-filter and computes their matches.
	EventTypeMatchingRecompute = "matching.recompute"
)

// Dedupe key namespaces of the matching job types. The outbox UQ
// (dedupe_key) is global across job types, so every key is prefixed with
// its job type — a rule version or a CVE list can never collide across
// job types or enqueue paths.
const (
	matchingRebuildDedupePrefix   = "matching.rebuild:"
	matchingRecomputeDedupePrefix = "matching.recompute:"
)

// MatchingRebuildPayload is the outbox payload of one matching.rebuild
// job (ARCH-003 §5, DEV-060): the identities of the rebuild — the
// composite rule version and the deterministic inventory snapshot hash
// its dedupe key is built from — plus the event envelope fields of the
// house style (event_id, type, occurred_at, correlation_id). It carries
// no secret: an inventory snapshot is derived from row counts and
// lifecycle stamps. The inventory commit (DEV-060) enqueues it; the
// WP-3.08 relay handler (internal/adapters/worker) consumes it.
type MatchingRebuildPayload struct {
	EventID           string    `json:"event_id"`
	Type              string    `json:"type"`
	ImportID          string    `json:"import_id"`
	RuleVersion       string    `json:"rule_version"`
	InventorySnapshot string    `json:"inventory_snapshot"`
	OccurredAt        time.Time `json:"occurred_at"`
	CorrelationID     string    `json:"correlation_id"`
}

// MatchingRecomputePayload is the outbox payload of one
// matching.recompute job (ARCH-003 §5): a pre-filtered batch of
// vulnerability row ids (≤ matchingRecomputeMaxIDs) that all carry
// inventory relevance under the current ruleset, the component_scope the
// batch was narrowed to (the affected products of the evidence change —
// "" when the batch was not scoped) and the composite rule version the
// batch was enqueued under (the rule_version half of the dedupe key).
// The envelope fields mirror the rebuild payload. It carries no secret:
// vulnerability ids are row identities, and the component scope is a
// normalised product name. The NVD incremental path (WP-3.09/DEV-052)
// enqueues it after the candidate pre-filter; the WP-3.08 relay handler
// (internal/adapters/worker) consumes it.
type MatchingRecomputePayload struct {
	EventID          string    `json:"event_id"`
	Type             string    `json:"type"`
	VulnerabilityIDs []string  `json:"vulnerability_ids"`
	ComponentScope   string    `json:"component_scope,omitempty"`
	RuleVersion      string    `json:"rule_version"`
	OccurredAt       time.Time `json:"occurred_at"`
	CorrelationID    string    `json:"correlation_id"`
}

// MatchingRebuildDedupeKey is the outbox dedupe key of one
// matching.rebuild job (ARCH-003 §5): "matching.rebuild:" namespacing the
// key (the outbox UQ is global across job types) followed by the
// composite effective rule version and the inventory snapshot hash — the
// two parts ARCH-003 §5 pins as the dedupe key. The outbox UQ
// (dedupe_key) makes the append idempotent for the whole job lifetime
// (ADR-012 point 4): an identical key can never enqueue twice, so a
// rebuild is enqueued exactly once per (rule version, inventory
// snapshot) pair.
func MatchingRebuildDedupeKey(ruleVersion, inventorySnapshot string) string {
	return matchingRebuildDedupePrefix + ruleVersion + ":" + inventorySnapshot
}

// MatchingRecomputeDedupeKey is the outbox dedupe key of one
// matching.recompute job (ARCH-003 §5): "matching.recompute:" namespacing
// the key, then the component scope, the composite rule version and the
// deterministic hash over the sorted vulnerability id list — the three
// parts the architecture pins as the dedupe key. The hash is computed
// over the ids sorted ascending, deduplicated and joined with "," (ids
// are uuids — they carry no separator character), so two payloads with
// the same id set in different orders — or with a repeated id — derive
// the same key and can never enqueue twice, while a different batch (an
// id added or removed) always derives a different key. The sort and
// dedupe happen on a copy — the caller's slice is never mutated.
func MatchingRecomputeDedupeKey(vulnerabilityIDs []string, componentScope, ruleVersion string) string {
	ids := append([]string(nil), vulnerabilityIDs...)
	sort.Strings(ids)
	uniq := ids[:0]
	var last string
	for _, id := range ids {
		if id == last {
			continue
		}
		uniq = append(uniq, id)
		last = id
	}
	sum := sha256.Sum256([]byte(strings.Join(uniq, ",")))
	return matchingRecomputeDedupePrefix + componentScope + ":" + ruleVersion + ":" + hex.EncodeToString(sum[:])
}
