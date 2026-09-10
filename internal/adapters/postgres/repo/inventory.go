package repo

// InventoryRepo is the postgres implementation of the WP-3.05 inventory
// import persistence ports (ARCH-003 §1.3, DEV-059/DEV-060): the
// read-only current-state port of the preview
// (application.InventoryRepo — pool-scoped, exercised by
// PreviewInventoryCSV) and the write path of the commit
// (application.InventoryWriter — every method on the caller's
// transaction, exercised by Service.CommitInventory inside
// postgres.WithTx). The queries live in assets.sql (the asset read and
// the clock-stamped import upsert), components.sql (the natural-key
// component upsert and the asset -> components read), the new
// inventory.sql (the §5 whole-inventory snapshot) and
// alias_rules.sql/decision_rules.sql (the ruleset version counters the
// composite rule version is derived from).
//
// Current-state mapping: a persisted asset is resolved by its import key
// (source, external_id — UQ (source, external_id), ARCH-003 §1.1) and
// rendered with its components as the preview diffs against them: the
// raw identifiers verbatim (NULL as ""), the natural key (the import
// idempotency key UQ (asset_id, natural_key), ARCH-003 §1.2) and the
// canonical asset row id the commit needs to upsert components under an
// already-persisted asset. The stored vocabulary columns are read back
// verbatim: every row was written through the domain parsers or the
// migration defaults, so the strings are canonical domain values. A
// legacy pre-I3 component row (nullable comparison keys, 'legacy:' md5
// natural key backfilled by migration 00005) renders like any other row
// — the preview classifies it by the key the parser derived, so a
// re-import of its identity rewrites the row through the I3 write path.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// InventoryRepo implements application.InventoryRepo (read) and
// application.InventoryWriter (write path) over one query set.
type InventoryRepo struct {
	q *gen.Queries
}

// NewInventoryRepo binds the repository to one query set.
func NewInventoryRepo(q *gen.Queries) *InventoryRepo { return &InventoryRepo{q: q} }

// compile-time checks that the repository satisfies both ports.
var (
	_ application.InventoryRepo   = (*InventoryRepo)(nil)
	_ application.InventoryWriter = (*InventoryRepo)(nil)
)

// CurrentAsset implements application.InventoryRepo: the pool-scoped
// current-state read of the preview.
func (r *InventoryRepo) CurrentAsset(ctx context.Context, source, externalID string) (application.CurrentInventoryAsset, bool, error) {
	return r.currentAsset(ctx, r.q, source, externalID)
}

// CurrentAssetOnTx implements application.InventoryWriter: the
// transaction-scoped current-state read of the commit, consistent with
// the commit's own writes (same transaction).
func (r *InventoryRepo) CurrentAssetOnTx(ctx context.Context, tx application.Tx, source, externalID string) (application.CurrentInventoryAsset, bool, error) {
	return r.currentAsset(ctx, r.q.WithTx(tx), source, externalID)
}

// currentAsset resolves one asset by its import key on the given query
// set (pool- or tx-bound) and renders it with its components. A missing
// asset is the normal "created" outcome of the preview: found=false, no
// error.
func (r *InventoryRepo) currentAsset(ctx context.Context, q *gen.Queries, source, externalID string) (application.CurrentInventoryAsset, bool, error) {
	const op = "inventory.current_asset"

	row, err := q.GetAssetBySourceExternalID(ctx, gen.GetAssetBySourceExternalIDParams{
		Source:     source,
		ExternalID: externalID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return application.CurrentInventoryAsset{}, false, nil
		}
		return application.CurrentInventoryAsset{}, false, mapDBError(op, err)
	}

	compRows, err := q.ListComponentsByAsset(ctx, row.ID)
	if err != nil {
		return application.CurrentInventoryAsset{}, false, mapDBError(op, err)
	}
	components := make([]application.CurrentInventoryComponent, 0, len(compRows))
	for _, c := range compRows {
		components = append(components, application.CurrentInventoryComponent{
			IDs: domain.ComponentIdentifiers{
				Vendor:  c.Vendor,
				Product: c.Product,
				Version: c.Version,
				CPE:     textValue(c.Cpe),
				PURL:    textValue(c.Purl),
				Image:   textValue(c.Image),
				Digest:  textValue(c.Digest),
			},
			NaturalKey: c.NaturalKey,
		})
	}

	return application.CurrentInventoryAsset{
		ID:          uuidString(row.ID),
		Source:      row.Source,
		ExternalID:  row.ExternalID,
		Type:        row.Type,
		Name:        row.Name,
		Environment: row.Environment,
		Criticality: row.Criticality,
		Exposure:    row.Exposure,
		Owner:       textValue(row.Owner),
		Components:  components,
	}, true, nil
}

// UpsertAsset implements application.InventoryWriter: the clock-stamped
// asset upsert of the import commit (ImportUpsertAsset — UQ (source,
// external_id), updated_at explicitly supplied; deactivated_at and
// verified_at are never touched by an import).
func (r *InventoryRepo) UpsertAsset(ctx context.Context, tx application.Tx, asset application.InventoryAsset, now time.Time) (string, error) {
	const op = "inventory.upsert_asset"

	id, err := r.q.WithTx(tx).ImportUpsertAsset(ctx, gen.ImportUpsertAssetParams{
		ExternalID:  asset.ExternalID,
		Source:      asset.Source,
		Type:        string(asset.Type),
		Name:        asset.Name,
		Environment: string(asset.Environment),
		Criticality: string(asset.Criticality),
		Exposure:    string(asset.Exposure),
		Owner:       toTextOpt(asset.Owner),
		UpdatedAt:   toTS(now),
	})
	if err != nil {
		return "", mapDBError(op, err)
	}
	return uuidString(id), nil
}

// UpsertComponent implements application.InventoryWriter: the
// natural-key component upsert of the import commit (InsertComponent —
// UQ (asset_id, natural_key), ARCH-003 §1.2/§1.3). The parsed component
// of the commit is persisted verbatim: raw identifiers as-is, the
// parser-derived normalised comparison keys and the parser-derived
// natural key (the key the preview classified on — domain.Component
// NaturalKey is applied exactly once, in the parser, and flows through
// validate/preview/commit unchanged). version_norm stays NULL: the CSV
// import layer has no version normaliser yet (the parser derives it as
// ""). updated_at is stamped from the injected clock; deactivated_at is
// never touched (additive upsert — absence never deactivates).
func (r *InventoryRepo) UpsertComponent(ctx context.Context, tx application.Tx, assetID string, comp application.InventoryComponent, now time.Time) error {
	const op = "inventory.upsert_component"

	aID, err := toUUID(assetID)
	if err != nil {
		return application.Validationf(op, "invalid asset id %q", assetID)
	}
	_, err = r.q.WithTx(tx).InsertComponent(ctx, gen.InsertComponentParams{
		AssetID:       aID,
		Vendor:        comp.IDs.Vendor,
		Product:       comp.IDs.Product,
		Version:       comp.IDs.Version,
		Cpe:           toTextOpt(comp.IDs.CPE),
		Purl:          toTextOpt(comp.IDs.PURL),
		Image:         toTextOpt(comp.IDs.Image),
		Digest:        toTextOpt(comp.IDs.Digest),
		VendorNorm:    comp.VendorNorm,
		ProductNorm:   comp.ProductNorm,
		VersionNorm:   toTextOpt(comp.VersionNorm),
		VersionScheme: string(comp.Scheme),
		NaturalKey:    comp.NaturalKey,
		UpdatedAt:     toTS(now),
	})
	return mapDBError(op, err)
}

// InventorySnapshot implements application.InventoryWriter: the ARCH-003
// §5 whole-inventory aggregates as visible on the transaction (the
// post-commit state of the running commit). Absent maxima map to the
// zero time (the snapshot hash renders them deterministically).
func (r *InventoryRepo) InventorySnapshot(ctx context.Context, tx application.Tx) (application.InventorySnapshot, error) {
	const op = "inventory.snapshot"

	row, err := r.q.WithTx(tx).InventorySnapshot(ctx)
	if err != nil {
		return application.InventorySnapshot{}, mapDBError(op, err)
	}
	return application.InventorySnapshot{
		AssetsCount:            int(row.AssetsCount),
		ComponentsCount:        int(row.ComponentsCount),
		AssetsMaxUpdatedAt:     tsTime(row.AssetsMaxUpdatedAt),
		ComponentsMaxUpdatedAt: tsTime(row.ComponentsMaxUpdatedAt),
		MaxDeactivatedAt:       tsTime(row.MaxDeactivatedAt),
	}, nil
}

// RuleVersions implements application.InventoryWriter: the current
// alias_rules and decision_rules version counters on the transaction
// (COALESCE(max(version), 0) — 0 when a table has no rules yet), the two
// halves of the composite effective rule version (domain.RulesetVersion,
// ARCH-003 §1.4/§3).
func (r *InventoryRepo) RuleVersions(ctx context.Context, tx application.Tx) (aliasVersion, decisionVersion int, err error) {
	const op = "inventory.rule_versions"

	alias, err := r.q.WithTx(tx).GetLatestAliasRulesVersion(ctx)
	if err != nil {
		return 0, 0, mapDBError(op, err)
	}
	decision, err := r.q.WithTx(tx).GetLatestDecisionRulesVersion(ctx)
	if err != nil {
		return 0, 0, mapDBError(op, err)
	}
	return int(alias), int(decision), nil
}

// textValue renders a nullable text column as "" when NULL — the
// convention of the application-layer types (originals are NULLable in
// the schema; the application model carries them as "").
func textValue(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// tsTime renders a nullable timestamptz column as the zero time when
// NULL — the application snapshot maps absent maxima to zero.
func tsTime(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}
