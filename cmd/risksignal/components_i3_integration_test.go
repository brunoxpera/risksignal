package main

// Integration test of the WP-3.03a I3 component write path (DEV-056 /
// DEV-058, ARCH-003 §1.2/§1.3/§4) at the composition root: the component
// upsert on UQ (asset_id, natural_key) and the inventory product index
// lookup over (vendor_norm, product_norm), on a real short-lived
// PostgreSQL. cmd/risksignal is the composition root that may wire the
// embedded migration set (db/migrations) together with the postgres
// adapter, so the schema and the generated queries (components.sql) are
// exercised here exactly as production wires them (demo.go
// seedDemoInventory — the I3 write path).
//
// The test drives the DEV-056 acceptance criterion on real rows:
//
//   - a component row carrying the I3 columns (normalised comparison keys,
//     the version scheme and the domain-derived natural key — the same
//     derivation the demo seed applies through seededComponentKey) upserts
//     under its asset and returns the canonical row id;
//   - the upsert is idempotent on the import idempotency key: the same
//     (asset_id, natural_key) write returns the same id and leaves exactly
//     one row (ARCH-003 §1.3);
//   - the inventory product index lookup ListComponentsByVendorProductNorm
//     resolves the row by its normalised pair (vendor_norm, product_norm)
//     — including when the raw originals differ in case from the folded
//     comparison keys — and returns the full I3 row (originals preserved
//     verbatim, natural key and clock-stamped updated_at round-trip);
//   - a norm pair with no inventory matches nothing, and the lookup filters
//     by the normalised product pair (a sibling product of the same asset
//     and vendor does not leak into the result).
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the tests skip (newMigratedTestPool), so `go test ./...` stays
// green on machines without the environment.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// TestComponentI3WritePathUpsertAndProductIndexLookup is the DEV-056
// acceptance test of the components write path: one asset, two components
// (portal / gateway), each written through InsertComponent with the I3
// columns. The portal row deliberately uses mixed-case raw originals
// ("Acme"/"Portal") so the folded comparison keys differ from the raw
// spellings — proving the product index lookup matches the normalised
// keys, not the originals.
func TestComponentI3WritePathUpsertAndProductIndexLookup(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)

	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID:  "asset-i3-portal",
		Source:      "demo",
		Type:        "server_vm",
		Name:        "I3 Portal",
		Environment: "production",
		Criticality: "critical",
		Exposure:    "internet",
		Owner:       pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}

	// The I3 write path derives the comparison keys and the natural key
	// from the row identity (seededComponentKey → domain.ComponentNaturalKey
	// — the same derivation NewComponent applies). The demo inventory has
	// no CPE/purl/image/digest identity, so the vendor/product(/version)
	// fallback is the key; the 'unknown' scheme normalises no version
	// (version_norm stays NULL — no fabricated ordering, ARCH-003 §2).
	updatedAt := mustTS(t, "2026-09-09T08:00:00Z")
	vendorNorm, productNorm, naturalKey, err := seededComponentKey("Acme", "Portal", "2.4")
	if err != nil {
		t.Fatalf("seededComponentKey: %v", err)
	}
	portalParams := gen.InsertComponentParams{
		AssetID:       assetID,
		Vendor:        "Acme",
		Product:       "Portal",
		Version:       "2.4",
		VendorNorm:    vendorNorm,
		ProductNorm:   productNorm,
		VersionScheme: string(domain.VersionSchemeUnknown),
		NaturalKey:    naturalKey,
		UpdatedAt:     updatedAt,
	}
	portalID, err := q.InsertComponent(ctx, portalParams)
	if err != nil {
		t.Fatalf("InsertComponent (portal): %v", err)
	}
	if !portalID.Valid {
		t.Fatal("InsertComponent returned an invalid id")
	}

	// Upsert idempotency on UQ (asset_id, natural_key): the identical write
	// returns the canonical row id and leaves exactly one component row.
	again, err := q.InsertComponent(ctx, portalParams)
	if err != nil {
		t.Fatalf("InsertComponent rerun: %v", err)
	}
	if again != portalID {
		t.Fatalf("InsertComponent rerun id = %v, want the canonical %v", again, portalID)
	}
	var portalCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM components WHERE asset_id = $1::uuid`, demoUUID(assetID)).Scan(&portalCount); err != nil {
		t.Fatalf("count portal components: %v", err)
	}
	if portalCount != 1 {
		t.Fatalf("components of the asset after re-upsert = %d, want 1 (UQ (asset_id, natural_key))", portalCount)
	}

	// A sibling component of the same asset and vendor, different product:
	// its own natural key, and it must not leak into the portal lookup.
	gatewayNormVendor, gatewayNormProduct, gatewayKey, err := seededComponentKey("Acme", "Gateway", "1.0")
	if err != nil {
		t.Fatalf("seededComponentKey (gateway): %v", err)
	}
	gatewayID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID:       assetID,
		Vendor:        "Acme",
		Product:       "Gateway",
		Version:       "1.0",
		VendorNorm:    gatewayNormVendor,
		ProductNorm:   gatewayNormProduct,
		VersionScheme: string(domain.VersionSchemeUnknown),
		NaturalKey:    gatewayKey,
		UpdatedAt:     updatedAt,
	})
	if err != nil {
		t.Fatalf("InsertComponent (gateway): %v", err)
	}

	// Product index lookup by the normalised pair: the mixed-case raw
	// originals ("Acme"/"Portal") are found through the folded keys
	// ("acme"/"portal") — IX components_product_idx (vendor_norm,
	// product_norm), ADR-012 / ARCH-003 §4.
	rows, err := q.ListComponentsByVendorProductNorm(ctx, gen.ListComponentsByVendorProductNormParams{
		VendorNorm:  "acme",
		ProductNorm: "portal",
	})
	if err != nil {
		t.Fatalf("ListComponentsByVendorProductNorm: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("product index lookup = %d row(s), want exactly the portal component", len(rows))
	}
	got := rows[0]
	if got.ID != portalID {
		t.Fatalf("product index row id = %v, want the portal component %v", got.ID, portalID)
	}
	if got.AssetID != assetID {
		t.Fatalf("product index row asset_id = %v, want %v", got.AssetID, assetID)
	}
	// Originals preserved verbatim; comparison keys and scheme round-trip.
	if got.Vendor != "Acme" || got.Product != "Portal" || got.Version != "2.4" {
		t.Fatalf("product index row raw originals = %s/%s/%s, want Acme/Portal/2.4", got.Vendor, got.Product, got.Version)
	}
	if got.VendorNorm != vendorNorm || got.ProductNorm != productNorm {
		t.Fatalf("product index row norms = %q/%q, want %q/%q", got.VendorNorm, got.ProductNorm, vendorNorm, productNorm)
	}
	if got.VersionScheme != string(domain.VersionSchemeUnknown) {
		t.Fatalf("product index row version_scheme = %q, want unknown", got.VersionScheme)
	}
	if got.NaturalKey != naturalKey {
		t.Fatalf("product index row natural_key = %q, want the derived %q", got.NaturalKey, naturalKey)
	}
	if got.VersionNorm.Valid {
		t.Fatalf("product index row version_norm = %q, want NULL ('unknown' normalises nothing)", got.VersionNorm.String)
	}
	if got.Cpe.Valid || got.Purl.Valid || got.Image.Valid || got.Digest.Valid {
		t.Fatal("product index row carries an identifier original, want all NULL (vendor/product fallback row)")
	}
	if got.DeactivatedAt.Valid {
		t.Fatal("product index row is deactivated, want active (deactivation is explicit lifecycle)")
	}
	if !got.UpdatedAt.Valid || !got.UpdatedAt.Time.Equal(updatedAt.Time) {
		t.Fatalf("product index row updated_at = %v, want the fixed clock instant %v", got.UpdatedAt, updatedAt.Time)
	}
	if got.UpdatedAt.Time.Location() != time.UTC {
		t.Fatalf("product index row updated_at location = %v, want time.UTC (pinUTCScan)", got.UpdatedAt.Time.Location())
	}

	// A lookup by a norm pair with no inventory matches nothing.
	none, err := q.ListComponentsByVendorProductNorm(ctx, gen.ListComponentsByVendorProductNormParams{
		VendorNorm:  "acme",
		ProductNorm: "missing",
	})
	if err != nil || len(none) != 0 {
		t.Fatalf("product index lookup (acme/missing) = %+v, %v; want no rows", none, err)
	}

	// The lookup filters by the normalised product pair: the gateway row of
	// the same asset/vendor is not a portal candidate.
	gatewayRows, err := q.ListComponentsByVendorProductNorm(ctx, gen.ListComponentsByVendorProductNormParams{
		VendorNorm:  "acme",
		ProductNorm: "gateway",
	})
	if err != nil || len(gatewayRows) != 1 || gatewayRows[0].ID != gatewayID {
		t.Fatalf("product index lookup (acme/gateway) = %+v, %v; want exactly the gateway component", gatewayRows, err)
	}
}
