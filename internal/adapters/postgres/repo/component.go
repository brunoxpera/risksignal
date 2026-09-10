package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// ComponentRepo is the postgres implementation of the component read ports
// (components.sql): the I1b matcher read over the seeded inventory
// (application.ComponentRepo — ARCH-001 §3 step 4), the I3 inventory
// product index lookup (application.ComponentNormLister — ADR-012,
// ARCH-003 §4) and the I3 matching reads of WP-3.08 (DEV-065): the
// keyset page walk of the matching.rebuild inventory loop and the by-id
// candidate row read of matching.recompute (application.MatchingComponents
// — ARCH-003 §5), all on one type. It is read-only — seeding is the I3
// import write path (InventoryRepo).
type ComponentRepo struct {
	q *gen.Queries
}

// NewComponentRepo binds the repository to one query set.
func NewComponentRepo(q *gen.Queries) *ComponentRepo { return &ComponentRepo{q: q} }

// compile-time checks that the repository satisfies the read ports.
var (
	_ application.ComponentRepo       = (*ComponentRepo)(nil)
	_ application.ComponentNormLister = (*ComponentRepo)(nil)
	_ application.MatchingComponents  = (*ComponentRepo)(nil)
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

// fullComponent maps the full I3 column set of one components row onto the
// application read model — the shared row mapping of the reads that return
// every column (the product index lookup, the keyset page walk, the by-id
// candidate read). The raw identifier originals travel verbatim (NULL as
// ""), the normalised comparison keys and the stored scheme pass through,
// and the lifecycle columns the model does not carry are dropped. A
// deactivated row maps like an active one — the matching engine decides
// what a deactivated component may still match (ARCH-003 §1.2).
func fullComponent(id, assetID pgtype.UUID, vendor, product, version string, cpe, purl, image, digest pgtype.Text, vendorNorm, productNorm string, versionNorm pgtype.Text, scheme string, naturalKey string) application.Component {
	return application.Component{
		ID:      uuidString(id),
		AssetID: uuidString(assetID),

		Vendor:  vendor,
		Product: product,
		Version: version,

		CPE:    textValue(cpe),
		PURL:   textValue(purl),
		Image:  textValue(image),
		Digest: textValue(digest),

		VendorNorm:    vendorNorm,
		ProductNorm:   productNorm,
		VersionNorm:   textValue(versionNorm),
		VersionScheme: domain.VersionScheme(scheme),
		NaturalKey:    naturalKey,
	}
}

// ListByVendorProductNorm implements application.ComponentNormLister: the
// full I3 row set of one normalised vendor/product pair — the inventory
// product index lookup of components.sql (ListComponentsByVendorProductNorm,
// IX components_product_idx ON (vendor_norm, product_norm)), in
// natural_key order — the full row the candidate pre-filter's semi-join
// returns and the matching run evaluates. Deactivated rows are returned
// like active ones — the matching engine decides what a deactivated
// component may still match (ARCH-003 §1.2).
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
		out = append(out, fullComponent(row.ID, row.AssetID, row.Vendor, row.Product, row.Version,
			row.Cpe, row.Purl, row.Image, row.Digest,
			row.VendorNorm, row.ProductNorm, row.VersionNorm, row.VersionScheme, row.NaturalKey))
	}
	return out, nil
}

// ListComponentsPage implements application.MatchingComponents: the
// bounded keyset walk of the matching.rebuild inventory loop — the
// components whose id is greater than afterID ("" = the first page),
// ascending by id, at most limit rows (ARCH-003 §5: components in batches
// of 500). Every walked row maps onto the full I3 read model; deactivated
// rows are returned like active ones (ARCH-003 §1.2). A page with no
// further rows is an empty slice, never an error.
func (r *ComponentRepo) ListComponentsPage(ctx context.Context, afterID string, limit int) ([]application.Component, error) {
	const op = "components.list_page"

	// The keyset cursor is a canonical uuid; "" (the first page) maps to
	// the zero uuid (valid, all-zero bytes), which sorts below every stored
	// id (gen_random_uuid never produces it), so the WHERE id > @after_id
	// of the query selects the first page unchanged.
	cursor := pgtype.UUID{Bytes: [16]byte{}, Valid: true}
	if afterID != "" {
		u, err := toUUID(afterID)
		if err != nil {
			return nil, application.ValidationError(op, err)
		}
		cursor = u
	}
	// components.page_limit is an int32 query parameter; reject a limit the
	// parameter type cannot hold instead of silently truncating it.
	if limit < 0 || limit > math.MaxInt32 {
		return nil, application.Validationf(op, "limit %d outside the int32 range", limit)
	}
	rows, err := r.q.ListComponentsPage(ctx, gen.ListComponentsPageParams{
		AfterID:   cursor,
		PageLimit: int32(limit),
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	out := make([]application.Component, 0, len(rows))
	for _, row := range rows {
		out = append(out, fullComponent(row.ID, row.AssetID, row.Vendor, row.Product, row.Version,
			row.Cpe, row.Purl, row.Image, row.Digest,
			row.VendorNorm, row.ProductNorm, row.VersionNorm, row.VersionScheme, row.NaturalKey))
	}
	return out, nil
}

// ListComponentsByIDs implements application.MatchingComponents: the full
// I3 rows of the given component ids, ascending by id (the candidate rows
// of one matching.recompute CVE, resolved by the pre-filter off the very
// same inventory — an id without a row is a torn read and therefore a
// not-found error, never a silent skip). An empty id list yields an empty
// slice without a query.
func (r *ComponentRepo) ListComponentsByIDs(ctx context.Context, ids []string) ([]application.Component, error) {
	const op = "components.list_by_ids"

	if len(ids) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return nil, application.InfraError(op, err)
	}
	rows, err := r.q.ListComponentsByIDs(ctx, b)
	if err != nil {
		return nil, mapDBError(op, err)
	}
	// An id without a row is a torn read: the pre-filter resolved the ids
	// off the components table this read queries, so a missing row means
	// the inventory changed between the two reads of one run.
	if len(rows) != len(ids) {
		found := make(map[string]struct{}, len(rows))
		for _, row := range rows {
			found[uuidString(row.ID)] = struct{}{}
		}
		for _, id := range ids {
			if _, ok := found[id]; !ok {
				return nil, application.NotFoundError(op, fmt.Errorf("component %s not found", id))
			}
		}
	}
	out := make([]application.Component, 0, len(rows))
	for _, row := range rows {
		out = append(out, fullComponent(row.ID, row.AssetID, row.Vendor, row.Product, row.Version,
			row.Cpe, row.Purl, row.Image, row.Digest,
			row.VendorNorm, row.ProductNorm, row.VersionNorm, row.VersionScheme, row.NaturalKey))
	}
	return out, nil
}
