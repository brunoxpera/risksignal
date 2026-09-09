package repo

import (
	"context"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
	"github.com/xpera/risksignal/internal/domain"
)

// ComponentRepo is the postgres implementation of the component read ports
// (components.sql): the I1b matcher read over the seeded inventory
// (application.ComponentRepo — ARCH-001 §3 step 4) and the I3 inventory
// product index lookup (application.ComponentNormLister — ADR-012,
// ARCH-003 §4), both on one type. It is read-only — seeding is the I3
// import write path (InventoryRepo).
type ComponentRepo struct {
	q *gen.Queries
}

// NewComponentRepo binds the repository to one query set.
func NewComponentRepo(q *gen.Queries) *ComponentRepo { return &ComponentRepo{q: q} }

// compile-time checks that the repository satisfies both read ports.
var (
	_ application.ComponentRepo       = (*ComponentRepo)(nil)
	_ application.ComponentNormLister = (*ComponentRepo)(nil)
)

// ListByVendorProduct implements application.ComponentRepo: the components
// of one vendor/product pair in version order; the matcher resolves the
// affected version range over the returned set. The I1b read selects no I3
// columns, so the returned rows carry the I3 fields empty.
func (r *ComponentRepo) ListByVendorProduct(ctx context.Context, vendor, product string) ([]application.Component, error) {
	const op = "components.list_by_vendor_product"

	rows, err := r.q.ListComponentsByVendorProduct(ctx, gen.ListComponentsByVendorProductParams{
		Vendor:  vendor,
		Product: product,
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.Component, 0, len(rows))
	for _, row := range rows {
		out = append(out, application.Component{
			ID:      uuidString(row.ID),
			AssetID: uuidString(row.AssetID),
			Vendor:  row.Vendor,
			Product: row.Product,
			Version: row.Version,
		})
	}
	return out, nil
}

// ListByVendorProductNorm implements application.ComponentNormLister: the
// full I3 row set of one normalised vendor/product pair — the inventory
// product index lookup of components.sql (ListComponentsByVendorProductNorm,
// IX components_product_idx ON (vendor_norm, product_norm)), in
// natural_key order. Every column of the row is mapped: the raw identifier
// originals verbatim (NULL as ""), the normalised comparison keys, the
// inferred version scheme and the import natural key — the full row the
// candidate pre-filter's semi-join returns and the matching run evaluates.
// Deactivated rows are returned like active ones — the matching engine
// decides what a deactivated component may still match (ARCH-003 §1.2).
func (r *ComponentRepo) ListByVendorProductNorm(ctx context.Context, vendorNorm, productNorm string) ([]application.Component, error) {
	const op = "components.list_by_vendor_product_norm"

	rows, err := r.q.ListComponentsByVendorProductNorm(ctx, gen.ListComponentsByVendorProductNormParams{
		VendorNorm:  vendorNorm,
		ProductNorm: productNorm,
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.Component, 0, len(rows))
	for _, row := range rows {
		out = append(out, application.Component{
			ID:      uuidString(row.ID),
			AssetID: uuidString(row.AssetID),

			Vendor:  row.Vendor,
			Product: row.Product,
			Version: row.Version,

			CPE:    textValue(row.Cpe),
			PURL:   textValue(row.Purl),
			Image:  textValue(row.Image),
			Digest: textValue(row.Digest),

			VendorNorm:    row.VendorNorm,
			ProductNorm:   row.ProductNorm,
			VersionNorm:   textValue(row.VersionNorm),
			VersionScheme: domain.VersionScheme(row.VersionScheme),
			NaturalKey:    row.NaturalKey,
		})
	}
	return out, nil
}
