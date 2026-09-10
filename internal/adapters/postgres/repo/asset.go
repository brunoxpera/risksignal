package repo

// AssetRepo is the postgres implementation of the I5b asset read port
// (ARCH-006 §2.2, WP-5b.02 / DEV-098): the cursor-paginated, filterable
// asset list (ListAssets, GET /assets) and the one-asset-with-components
// read (GetAssetComponents, GET /assets/{id}/components) that back the I5b
// inventory read use cases (WP-5b.03).
//
// It is read-only and pool-scoped — inventory mutation stays the I3 import
// write path (InventoryRepo/InventoryWriter, DEV-059/060) — and it reuses
// the I3 indexes: the asset list walks the table by (created_at, id) and
// the components read resolves through IX components_asset_id_idx. The
// stored vocabulary columns are read back verbatim and cast onto the domain
// enums (every row was written through the domain parsers or the migration
// defaults, so the strings are canonical values — the same convention as
// the signal read mapping). The adapter maps rows onto the application
// read models (Asset/Component) and does no identity/principal mapping:
// the object-scope filter is the plain owner_id filter the caller supplies,
// never a principal resolved here.

import (
	"context"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// AssetRepo implements application.AssetRepo over one query set.
type AssetRepo struct {
	q *gen.Queries
}

// NewAssetRepo binds the repository to one query set.
func NewAssetRepo(q *gen.Queries) *AssetRepo { return &AssetRepo{q: q} }

// compile-time check that the repository satisfies the read port.
var _ application.AssetRepo = (*AssetRepo)(nil)

// ListAssets implements application.AssetRepo (ARCH-006 §2.2): one page of
// the asset working list ordered by created_at then id (a stable sort). The
// filters narrow the read — a nil field keeps it open — and OwnerID is the
// object-scope injection point. The window is fetched as offset+limit+1 rows
// (so the caller can detect a further page) and offset into in Go, exactly
// like SignalRepo.List; the slice is empty when the offset is past the last
// row.
func (r *AssetRepo) ListAssets(ctx context.Context, filter application.AssetFilter, limit, offset int) ([]application.Asset, error) {
	const op = "assets.list"

	if offset < 0 {
		return nil, application.Validationf(op, "negative offset")
	}
	// The window is computed in int64 so the addition cannot overflow, then
	// checked against the int32 max_rows parameter: an overflowing window
	// (negative limit or an offset near MaxInt) is a validation error, never
	// a silent truncation.
	maxRows := int64(offset) + int64(limit) + 1
	if maxRows <= 0 || maxRows > math.MaxInt32 {
		return nil, application.Validationf(op, "page window offset+limit+1 = %d outside [1,%d]", maxRows, math.MaxInt32)
	}
	rows, err := r.q.ListAssets(ctx, gen.ListAssetsParams{
		Type:        toTextOptPtr(filter.Type),
		Environment: toTextOptPtr(filter.Environment),
		Criticality: toTextOptPtr(filter.Criticality),
		Exposure:    toTextOptPtr(filter.Exposure),
		OwnerID:     toTextOptPtr(filter.OwnerID),
		Source:      toTextOptPtr(filter.Source),
		MaxRows:     int32(maxRows),
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	if offset >= len(rows) {
		return []application.Asset{}, nil
	}
	rows = rows[offset:]
	out := make([]application.Asset, 0, len(rows))
	for _, row := range rows {
		out = append(out, assetFromColumns(
			row.ID, row.ExternalID, row.Source, row.Type, row.Name,
			row.Environment, row.Criticality, row.Exposure, row.Owner,
			row.CreatedAt, row.UpdatedAt, row.DeactivatedAt, row.VerifiedAt,
		))
	}
	return out, nil
}

// GetAssetComponents implements application.AssetRepo (ARCH-006 §2.2): one
// asset together with its components, ordered by natural_key. The read is a
// LEFT JOIN, so a component-less asset still returns one row with NULL
// component columns (mapped to the asset with an empty component slice) and
// an unknown asset id returns no rows — mapped to a not-found error.
func (r *AssetRepo) GetAssetComponents(ctx context.Context, assetID string) (application.AssetComponents, error) {
	const op = "assets.get_components"

	id, err := toUUID(assetID)
	if err != nil {
		return application.AssetComponents{}, application.ValidationError(op, err)
	}
	rows, err := r.q.GetAssetComponents(ctx, id)
	if err != nil {
		return application.AssetComponents{}, mapDBError(op, err)
	}
	if len(rows) == 0 {
		return application.AssetComponents{}, application.NotFoundError(op, fmt.Errorf("asset %s not found", assetID))
	}
	first := rows[0]
	res := application.AssetComponents{
		Asset: assetFromColumns(
			first.ID, first.ExternalID, first.Source, first.Type, first.Name,
			first.Environment, first.Criticality, first.Exposure, first.Owner,
			first.CreatedAt, first.UpdatedAt, first.DeactivatedAt, first.VerifiedAt,
		),
		Components: make([]application.Component, 0, len(rows)),
	}
	for _, row := range rows {
		// The LEFT JOIN emits one all-NULL component row for a component-less
		// asset: the NULL component id is the marker that this row carries no
		// component (a real component row always has a non-NULL id).
		if !row.ComponentID.Valid {
			continue
		}
		res.Components = append(res.Components, fullComponent(
			row.ComponentID, row.ID,
			textValue(row.ComponentVendor), textValue(row.ComponentProduct), textValue(row.ComponentVersion),
			row.ComponentCpe, row.ComponentPurl, row.ComponentImage, row.ComponentDigest,
			textValue(row.ComponentVendorNorm), textValue(row.ComponentProductNorm),
			row.ComponentVersionNorm, textValue(row.ComponentVersionScheme), textValue(row.ComponentNaturalKey),
		))
	}
	return res, nil
}

// assetFromColumns maps the asset column block of a ListAssets or
// GetAssetComponents row onto the application read model. The stored
// vocabulary strings cast onto the domain enums (canonical values — every
// row was written through the domain parsers or the migration defaults);
// the two nullable lifecycle instants render as the zero time when NULL
// (DeactivatedAt zero ⇒ active, VerifiedAt zero ⇒ never verified).
func assetFromColumns(
	id pgtype.UUID,
	externalID, source, typ, name, environment, criticality, exposure string,
	owner pgtype.Text,
	createdAt, updatedAt, deactivatedAt, verifiedAt pgtype.Timestamptz,
) application.Asset {
	return application.Asset{
		ID:            uuidString(id),
		ExternalID:    externalID,
		Source:        source,
		Type:          domain.AssetType(typ),
		Name:          name,
		Environment:   domain.Environment(environment),
		Criticality:   domain.Criticality(criticality),
		Exposure:      domain.Exposure(exposure),
		Owner:         textValue(owner),
		CreatedAt:     createdAt.Time,
		UpdatedAt:     updatedAt.Time,
		DeactivatedAt: tsTime(deactivatedAt),
		VerifiedAt:    tsTime(verifiedAt),
	}
}
