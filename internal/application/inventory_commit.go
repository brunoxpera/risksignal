package application

// This file implements the commit use case of the WP-3.05 inventory
// import (ARCH-003 §1.3 step 3, DEV-060): CommitInventory turns one
// parsed inventory CSV into persisted state — one domain command, one
// transaction (ch. 5.1). The transaction
//
//  1. classifies every parsed asset group against the current state read
//     ON THE SAME TRANSACTION (diffAsset — the exact pure classification
//     the preview of DEV-059 renders, so commit and preview always
//     agree: the natural key every write upserts on is the key the
//     parser derived through domain.ComponentNaturalKey and the preview
//     compared);
//  2. writes only what actually changed — the additive upsert of
//     ARCH-003 §1.3: assets on UQ (source, external_id), components on
//     UQ (asset_id, natural_key), both stamped with updated_at from the
//     injected clock. Absence never deactivates: rows of the current
//     state the file does not carry stay untouched, and the upsert
//     statements never touch deactivated_at (deactivation is explicit
//     lifecycle, never an import side effect). Unchanged rows are not
//     rewritten at all — a re-commit of identical content is a true
//     no-op that leaves even updated_at alone;
//  3. writes the audit event of the action (inventory.import, ch. 13.2 —
//     every commit attempt is audited with the accurate counts, also
//     when it changed nothing);
//  4. and — only when the commit changed at least one row — enqueues
//     exactly one matching.rebuild job (outbox, same transaction) whose
//     dedupe key is rule_version + inventory_snapshot (ARCH-003 §5,
//     ADR-012): the composite effective rule version
//     (domain.RulesetVersion over the alias_rules and decision_rules
//     version counters) plus the deterministic §5 hash over
//     (count(assets), count(components), max(assets.updated_at),
//     max(components.updated_at), max(deactivated_at)) captured after
//     the commit's own writes on the same transaction. The outbox UQ
//     (dedupe_key) then holds for the whole job lifetime (ADR-012 point
//     4): a later import that changes the inventory derives a new
//     snapshot (its clock stamp advances the max updated_at) and
//     enqueues a fresh rebuild; an import that changes nothing enqueues
//     nothing.
//
// Rows with positioned problems never write: the parser excludes them
// from the parsed assets, so a commit applies exactly the clean rows the
// validate/preview report showed, next to the problems that blocked the
// rejected rows ("preview shows exactly what a commit of the file's
// clean rows would change, next to the errors that would block those
// rows", ARCH-003 §1.3). The matching.rebuild handler is WP-3.08
// (DEV-051) — this use case only enqueues the job.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brunoxpera/risksignal/internal/domain"
	"github.com/brunoxpera/risksignal/internal/platform/uuid"
)

// Audit and outbox vocabulary of the inventory commit (ch. 13.2
// "Inventarimport" is auditable; ARCH-003 §1.3/§5). The matching.rebuild
// event type, payload and dedupe key builder are the shared matching-job
// contract of matching_jobs.go (WP-3.08) — the commit only enqueues the
// job; the relay handler consumes it.
const (
	// AuditAggregateInventory is the aggregate type of inventory audit
	// rows. The aggregate id of one commit is the generated import id
	// (ImportID) — the CLI path has no persisted import row yet; the I5b
	// API import workflow will make the id reference one.
	AuditAggregateInventory = "inventory"

	// AuditActionInventoryImport records an inventory import commit.
	AuditActionInventoryImport = "inventory.import"

	// defaultInventoryActorID is the I2 audit actor of the inventory
	// commands: a system principal (ch. 13.2 — user principals arrive
	// with I5a), the same "operator" the quarantine review commands use.
	defaultInventoryActorID = "operator"
)

// InventoryWriter is the persistence half of the inventory commit
// (ARCH-003 §1.3 step 3, WP-3.05b / DEV-060): the current-state read and
// the additive upserts of one commit, every method running on the
// caller's transaction — the transaction postgres.WithTx opens for the
// command, so state change, audit event and the matching.rebuild outbox
// row commit or roll back together (ch. 5.1). The DEV-059 read-only
// current-state port of the preview (InventoryRepo) is deliberately
// separate; the postgres adapter (internal/adapters/postgres/repo)
// implements both on one type.
type InventoryWriter interface {
	// CurrentAssetOnTx resolves one asset by its import key
	// (source, external_id) together with its components ON the given
	// transaction — the current-state read of the commit, consistent
	// with its own writes (the preview reads the same shape off the
	// pool through InventoryRepo.CurrentAsset).
	CurrentAssetOnTx(ctx context.Context, tx Tx, source, externalID string) (CurrentInventoryAsset, bool, error)

	// UpsertAsset inserts or refreshes one parsed asset group's row by
	// UQ (source, external_id) on the transaction and returns the
	// canonical row id (freshly inserted or already existing). The
	// write stamps updated_at with now (the injected clock) and never
	// touches deactivated_at — additive upsert, deactivation stays
	// explicit lifecycle (ARCH-003 §1.1/§1.3).
	UpsertAsset(ctx context.Context, tx Tx, asset InventoryAsset, now time.Time) (string, error)

	// UpsertComponent inserts or refreshes one parsed component row of
	// an asset by UQ (asset_id, natural_key) on the transaction — the
	// exact parsed values of the row (raw identifiers verbatim, the
	// derived comparison keys and the parser-derived natural key, the
	// key preview compared), updated_at stamped from the injected
	// clock. Never touches deactivated_at.
	UpsertComponent(ctx context.Context, tx Tx, assetID string, comp InventoryComponent, now time.Time) error

	// InventorySnapshot returns the ARCH-003 §5 inventory aggregates as
	// visible on the transaction — counts and max lifecycle stamps over
	// assets and components — captured after the commit's own upserts,
	// the input of the deterministic snapshot hash of the
	// matching.rebuild dedupe key.
	InventorySnapshot(ctx context.Context, tx Tx) (InventorySnapshot, error)

	// RuleVersions returns the current alias_rules and decision_rules
	// version counters on the transaction — the two halves of the
	// composite effective rule version (domain.RulesetVersion,
	// "a<alias.version>d<decision.version>") that flows into the
	// matching.rebuild dedupe key and, from WP-3.06 on, into every
	// match row.
	RuleVersions(ctx context.Context, tx Tx) (aliasVersion, decisionVersion int, err error)
}

// InventorySnapshot is the ARCH-003 §5 inventory state summary one
// matching.rebuild dedupe key is derived from: the row counts and the
// newest lifecycle stamps of assets and components (max(deactivated_at)
// spans both tables). A zero timestamp means the table side has no rows
// (or no deactivated row) yet. Counts are the database bigint counts
// converted to int — bounded by the import limits of the parser
// (InventoryMaxRows).
type InventorySnapshot struct {
	AssetsCount            int
	ComponentsCount        int
	AssetsMaxUpdatedAt     time.Time // zero when the assets table is empty
	ComponentsMaxUpdatedAt time.Time // zero when the components table is empty
	MaxDeactivatedAt       time.Time // zero when no row of either table is deactivated
}

// CommitInventoryInput is the inventory commit command (ARCH-003 §1.3
// step 3): the CSV content to commit (the canonical §1.3 shape; bounded
// by InventoryMaxBytes through the parser — an oversized file is
// rejected before any write), the audit actor and an optional
// correlation id linking the audit row and the matching.rebuild outbox
// row of the command (empty generates one, like CreateSignal).
type CommitInventoryInput struct {
	File          []byte
	Actor         Actor
	CorrelationID string
}

// CommitInventoryResult is the report of one inventory commit: the
// parse-level row/error/warning counts (a failing row never aborts the
// file and never writes — ARCH-003 §1.3), the created/updated/unchanged
// tallies of the exact classification preview would have rendered, and
// the commit outcome: Changed reports whether any row was written,
// ImportID the generated aggregate id of the commit, CorrelationID the
// id linking the audit row and the outbox row, and — when Changed —
// RuleVersion and InventorySnapshot describe the enqueued
// matching.rebuild job (its dedupe key is
// "matching.rebuild:<rule_version>:<snapshot>"). On a no-op re-commit
// Changed is false and no job was enqueued: the commit is idempotent at
// the data level (the upsert natural keys) and at the job level (a
// rebuild only follows an actual change).
type CommitInventoryResult struct {
	ImportID      string
	CorrelationID string

	Rows       int
	ErrorCount int
	Errors     []InventoryProblem
	Warnings   []InventoryWarning

	AssetsCreated   int
	AssetsUpdated   int
	AssetsUnchanged int

	ComponentsCreated   int
	ComponentsUpdated   int
	ComponentsUnchanged int

	Changed           bool
	RuleVersion       string // "" when Changed is false
	InventorySnapshot string // "" when Changed is false (64-hex sha-256, ARCH-003 §5)
}

// CommitInventory parses and commits one inventory CSV (ARCH-003 §1.3
// step 3) in one transaction: parse (pure — every positioned problem is
// reported, never fatal, and a problem row never writes), then inside
// postgres.WithTx the current-state classification of every clean asset
// group, the additive upserts of the changed rows, the audit event and —
// only for a commit that changed something — exactly one
// matching.rebuild job. A failure of any write — the audit append or the
// outbox append (the ARCH-003 §5/§1.3 fault seam) — propagates unwrapped
// and rolls the whole transaction back: no inventory-without-audit,
// audit-without-job or job-without-state half-state can exist (TR-004).
//
// The parse-level resource failures (input at or above InventoryMaxBytes,
// unreadable input) are returned before any transaction is opened.
func (s *Service) CommitInventory(ctx context.Context, in CommitInventoryInput) (CommitInventoryResult, error) {
	const op = "inventory_commit"

	// inventory.manage (Administrator-scope per the matrix): denied before the
	// parse and before any transaction, so a denied commit writes nothing
	// (ARCH-005 §5).
	if _, err := s.authorize(ctx, op, in.Actor, domain.PermissionInventoryManage, domain.ScopeAll, ""); err != nil {
		return CommitInventoryResult{}, err
	}
	actor := inventoryActor(in.Actor)
	file, err := ParseInventoryCSV(bytes.NewReader(in.File))
	if err != nil {
		return CommitInventoryResult{}, err
	}
	importID := uuid.New()
	correlationID := in.CorrelationID
	if correlationID == "" {
		correlationID = uuid.New()
	}

	res := CommitInventoryResult{
		ImportID:      importID,
		CorrelationID: correlationID,
		Rows:          file.Rows,
		ErrorCount:    len(file.Problems),
		Errors:        file.Problems,
		Warnings:      file.Warnings,
	}

	err = s.runTx(ctx, func(tx Tx) error {
		now := s.clock.Now()

		// 1) classify every clean asset group against the current state
		// on this transaction and 2) write exactly what changed.
		changed := false
		for i := range file.Assets {
			a := &file.Assets[i]
			cur, found, err := s.inventory.CurrentAssetOnTx(ctx, tx, a.Source, a.ExternalID)
			if err != nil {
				return err
			}
			diff := diffAsset(a, cur, found)
			switch diff.Status {
			case AssetCreated:
				res.AssetsCreated++
			case AssetUpdated:
				res.AssetsUpdated++
			default:
				res.AssetsUnchanged++
			}

			assetID := cur.ID
			if diff.Status != AssetUnchanged {
				// The asset row differs (or does not exist yet): refresh
				// it and take the canonical row id from the write.
				assetID, err = s.inventory.UpsertAsset(ctx, tx, *a, now)
				if err != nil {
					return err
				}
				changed = true
			}
			for ci, cd := range diff.Components {
				switch cd.Status {
				case AssetCreated:
					res.ComponentsCreated++
				case AssetUpdated:
					res.ComponentsUpdated++
				default:
					res.ComponentsUnchanged++
					continue
				}
				// An unchanged asset still needs its canonical id for the
				// component writes: found assets carry it in cur.ID.
				if err := s.inventory.UpsertComponent(ctx, tx, assetID, a.Components[ci], now); err != nil {
					return err
				}
				changed = true
			}
		}

		// 3) audit event (same transaction; the after snapshot is the
		// minimised commit report of ch. 13.5 — counts and job
		// description only, no secrets; before stays NULL: an import
		// commit has no single prior aggregate state).
		after, err := json.Marshal(inventoryImportSnapshot{
			ImportID:          importID,
			Changed:           changed,
			AssetsCreated:     res.AssetsCreated,
			AssetsUpdated:     res.AssetsUpdated,
			ComponentsCreated: res.ComponentsCreated,
			ComponentsUpdated: res.ComponentsUpdated,
		})
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.audit.Append(ctx, tx, AuditEvent{
			AggregateType:    AuditAggregateInventory,
			AggregateID:      importID,
			ActorType:        actor.Type,
			ActorID:          actor.ID,
			ActorDisplayName: actor.DisplayName,
			Action:           AuditActionInventoryImport,
			OccurredAt:       now,
			Before:           nil,
			After:            after,
			CorrelationID:    correlationID,
		}); err != nil {
			return err
		}

		// 4) exactly one matching.rebuild job — only when the commit
		// actually changed inventory (a no-op re-commit enqueues nothing;
		// ARCH-003 §5: a rebuild follows a snapshot change).
		if !changed {
			return nil
		}
		snap, err := s.inventory.InventorySnapshot(ctx, tx)
		if err != nil {
			return err
		}
		snapshotHash := inventorySnapshotHash(snap)
		aliasVersion, decisionVersion, err := s.inventory.RuleVersions(ctx, tx)
		if err != nil {
			return err
		}
		ruleVersion, err := domain.RulesetVersion(aliasVersion, decisionVersion)
		if err != nil {
			return InfraError(op, err)
		}
		payload, err := json.Marshal(MatchingRebuildPayload{
			EventID:           uuid.New(),
			Type:              EventTypeMatchingRebuild,
			ImportID:          importID,
			RuleVersion:       ruleVersion,
			InventorySnapshot: snapshotHash,
			OccurredAt:        now,
			CorrelationID:     correlationID,
		})
		if err != nil {
			return InfraError(op, err)
		}
		if err := s.outbox.Append(ctx, tx, OutboxEvent{
			Type:        EventTypeMatchingRebuild,
			Payload:     payload,
			DedupeKey:   MatchingRebuildDedupeKey(ruleVersion, snapshotHash),
			AvailableAt: now,
			CreatedAt:   now,
		}); err != nil {
			return err
		}
		res.Changed = true
		res.RuleVersion = ruleVersion
		res.InventorySnapshot = snapshotHash
		return nil
	})
	if err != nil {
		return CommitInventoryResult{}, err
	}
	return res, nil
}

// inventoryImportSnapshot is the minimised after snapshot of an
// inventory.import audit event (ch. 13.5: counts and outcome only — the
// CSV content never travels into the audit row; it is not a secret, but
// it is not a state snapshot either).
type inventoryImportSnapshot struct {
	ImportID string `json:"import_id"`
	Changed  bool   `json:"changed"`

	AssetsCreated     int `json:"assets_created"`
	AssetsUpdated     int `json:"assets_updated"`
	ComponentsCreated int `json:"components_created"`
	ComponentsUpdated int `json:"components_updated"`
}

// The matching.rebuild outbox payload type (MatchingRebuildPayload) and
// the dedupe key builder (MatchingRebuildDedupeKey) live in
// matching_jobs.go — the shared matching-job contract of WP-3.08 both
// the enqueue side and the relay handlers compile against.
// inventorySnapshotHash derives the deterministic ARCH-003 §5 hash of one
// inventory snapshot — sha-256 (64 hex) over the canonical
// pipe-separated rendering of the five aggregates, RFC 3339 nanosecond
// UTC for the timestamps ("" for an absent stamp, so an empty table side
// renders deterministically). Same input always yields the same hash;
// any inventory mutation advances a max updated_at stamp of the commit
// that caused it, so the hash of a changed inventory differs from every
// earlier enqueue (the injected clock is monotonic in practice).
func inventorySnapshotHash(s InventorySnapshot) string {
	part := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	input := fmt.Sprintf("%d|%d|%s|%s|%s",
		s.AssetsCount, s.ComponentsCount,
		part(s.AssetsMaxUpdatedAt), part(s.ComponentsMaxUpdatedAt), part(s.MaxDeactivatedAt))
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// inventoryActor defaults the audit actor of the inventory commands:
// empty Actor (the CLI takes no identity input before I5a) becomes the
// system principal "operator", like the quarantine review commands.
func inventoryActor(a Actor) Actor {
	if a.Type == "" {
		a.Type = ActorTypeSystem
	}
	if a.ID == "" {
		a.ID = defaultInventoryActorID
	}
	return a
}
