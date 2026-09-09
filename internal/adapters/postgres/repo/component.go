package repo

import (
	"context"

	"github.com/xpera/risksignal/internal/adapters/postgres/gen"
	"github.com/xpera/risksignal/internal/application"
)

// ComponentRepo is the postgres implementation of application.ComponentRepo
// (components.sql): the I1b matcher read over the seeded inventory
// (ARCH-001 §3 step 4). It is read-only — seeding is WP-1b.05's demo path.
type ComponentRepo struct {
	q *gen.Queries
}

// NewComponentRepo binds the repository to one query set.
func NewComponentRepo(q *gen.Queries) *ComponentRepo { return &ComponentRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.ComponentRepo = (*ComponentRepo)(nil)

// ListByVendorProduct implements application.ComponentRepo: the components
// of one vendor/product pair in version order; the matcher resolves the
// affected version range over the returned set.
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
