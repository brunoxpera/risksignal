package main

// Integration test of the WP-3.08a ComponentRepo lister wiring (DEV-063,
// ARCH-003 §1.2/§4) at the composition root: the repo adapter's
// ListByVendorProductNorm — the inventory product index lookup serving the
// candidate pre-filter and the matching run (ADR-012) — returns the full
// I3 component row through application.Component, on a real short-lived
// PostgreSQL. cmd/risksignal is the composition root that may wire the
// embedded migration set (db/migrations) together with the postgres
// adapter, so the schema and the generated query (components.sql
// ListComponentsByVendorProductNorm) are exercised through the repository
// port exactly as production wires them.
//
// The test drives the DEV-063 lister acceptance criterion on real rows: a
// component row carrying the full I3 shape (raw identifier originals
// cpe/purl/image/digest, the normalised comparison keys, the inferred
// version scheme, a normalised version and the domain-derived natural key)
// is resolved by its normalised (vendor_norm, product_norm) pair and every
// I3 field round-trips through the extended application.Component model —
// originals preserved verbatim, the scheme mapped to the domain vocabulary,
// the NULLable columns (no purl, no version_norm on the sibling) as "". A
// norm pair with no inventory matches nothing, and the lookup filters by
// the normalised product pair (a sibling product of the same asset and
// vendor does not leak into the result).
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
	"github.com/brunoxpera/risksignal/internal/adapters/postgres/repo"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// TestComponentListerReturnsFullI3Rows is the DEV-063 lister acceptance
// test: seed one asset with a portal component carrying the full I3 shape
// (cpe/purl/image/digest + normalised keys + semver scheme + natural key)
// and a gateway sibling, then resolve the portal row through the repo
// adapter's ListByVendorProductNorm and assert the complete round trip.
// The portal row deliberately uses mixed-case raw originals ("Acme"/
// "Portal") so the folded comparison keys differ from the raw spellings —
// proving the product index lookup matches the normalised keys, not the
// originals.
func TestComponentListerReturnsFullI3Rows(t *testing.T) {
	pool := newMigratedTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	q := gen.New(pool)
	lister := repo.NewComponentRepo(q)

	assetID, err := q.UpsertAsset(ctx, gen.UpsertAssetParams{
		ExternalID:  "asset-i3-lister",
		Source:      "demo",
		Type:        "server_vm",
		Name:        "I3 Lister Portal",
		Environment: "production",
		Criticality: "critical",
		Exposure:    "internet",
		Owner:       pgtype.Text{},
	})
	if err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}

	// The I3 write path supplies the normalised comparison keys and the
	// import idempotency natural key (seededComponentKey →
	// domain.ComponentNaturalKey — the same derivation NewComponent
	// applies). The portal row additionally carries the raw identifier
	// originals (CPE + purl + image + digest) and a normalised version
	// under the semver scheme, so every I3 column of the lookup row is
	// exercised.
	updatedAt := mustTS(t, "2026-09-09T08:00:00Z")
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	vendorNorm, productNorm, naturalKey, err := seededComponentKey("Acme", "Portal", "2.4")
	if err != nil {
		t.Fatalf("seededComponentKey (portal): %v", err)
	}
	portalID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID:       assetID,
		Vendor:        "Acme",
		Product:       "Portal",
		Version:       "2.4",
		Cpe:           demoTextOpt("cpe:2.3:a:acme:portal:2.4:*:*:*:*:*:*:*"),
		Purl:          demoTextOpt("pkg:golang/github.com/acme/portal@2.4.0"),
		Image:         demoTextOpt("registry.example.com/acme/portal:2.4@" + digest),
		Digest:        demoTextOpt(digest),
		VendorNorm:    vendorNorm,
		ProductNorm:   productNorm,
		VersionNorm:   demoTextOpt("2.4.0"),
		VersionScheme: string(domain.VersionSchemeSemver),
		NaturalKey:    naturalKey,
		UpdatedAt:     updatedAt,
	})
	if err != nil {
		t.Fatalf("InsertComponent (portal): %v", err)
	}

	// A sibling component of the same asset and vendor, different product:
	// its own natural key, no identifiers, 'unknown' scheme, no normalised
	// version — it must not leak into the portal lookup.
	gatewayVendorNorm, gatewayProductNorm, gatewayKey, err := seededComponentKey("Acme", "Gateway", "1.0")
	if err != nil {
		t.Fatalf("seededComponentKey (gateway): %v", err)
	}
	gatewayID, err := q.InsertComponent(ctx, gen.InsertComponentParams{
		AssetID:       assetID,
		Vendor:        "Acme",
		Product:       "Gateway",
		Version:       "1.0",
		VendorNorm:    gatewayVendorNorm,
		ProductNorm:   gatewayProductNorm,
		VersionScheme: string(domain.VersionSchemeUnknown),
		NaturalKey:    gatewayKey,
		UpdatedAt:     updatedAt,
	})
	if err != nil {
		t.Fatalf("InsertComponent (gateway): %v", err)
	}

	// Product index lookup through the adapter: the mixed-case raw
	// originals ("Acme"/"Portal") are found through the folded keys
	// ("acme"/"portal") and the full I3 row round-trips.
	rows, err := lister.ListByVendorProductNorm(ctx, "acme", "portal")
	if err != nil {
		t.Fatalf("ListByVendorProductNorm: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListByVendorProductNorm (acme/portal) = %d row(s), want exactly the portal component", len(rows))
	}
	got := rows[0]
	if got.ID != demoUUID(portalID) {
		t.Fatalf("row id = %q, want the portal component %s", got.ID, demoUUID(portalID))
	}
	if got.AssetID != demoUUID(assetID) {
		t.Fatalf("row asset_id = %q, want %s", got.AssetID, demoUUID(assetID))
	}
	// Raw originals preserved verbatim, identifiers included.
	if got.Vendor != "Acme" || got.Product != "Portal" || got.Version != "2.4" {
		t.Fatalf("row raw originals = %s/%s/%s, want Acme/Portal/2.4", got.Vendor, got.Product, got.Version)
	}
	if got.CPE != "cpe:2.3:a:acme:portal:2.4:*:*:*:*:*:*:*" {
		t.Fatalf("row cpe = %q, want the verbatim original", got.CPE)
	}
	if got.PURL != "pkg:golang/github.com/acme/portal@2.4.0" {
		t.Fatalf("row purl = %q, want the verbatim original", got.PURL)
	}
	if got.Image != "registry.example.com/acme/portal:2.4@"+digest {
		t.Fatalf("row image = %q, want the verbatim original", got.Image)
	}
	if got.Digest != digest {
		t.Fatalf("row digest = %q, want the verbatim original", got.Digest)
	}
	// Normalised comparison keys, the normalised version and the scheme
	// round-trip; the natural key is the derived import key.
	if got.VendorNorm != vendorNorm || got.ProductNorm != productNorm {
		t.Fatalf("row norms = %q/%q, want %q/%q", got.VendorNorm, got.ProductNorm, vendorNorm, productNorm)
	}
	if got.VersionNorm != "2.4.0" {
		t.Fatalf("row version_norm = %q, want 2.4.0", got.VersionNorm)
	}
	if got.VersionScheme != domain.VersionSchemeSemver {
		t.Fatalf("row version_scheme = %q, want semver", got.VersionScheme)
	}
	if got.NaturalKey != naturalKey {
		t.Fatalf("row natural_key = %q, want the derived %q", got.NaturalKey, naturalKey)
	}

	// A lookup by a norm pair with no inventory matches nothing.
	if none, err := lister.ListByVendorProductNorm(ctx, "acme", "missing"); err != nil || len(none) != 0 {
		t.Fatalf("ListByVendorProductNorm (acme/missing) = %+v, %v; want no rows", none, err)
	}

	// The lookup filters by the normalised product pair: the gateway row of
	// the same asset/vendor is not a portal candidate, and its own lookup
	// returns the NULLable I3 columns as "" (no identifiers, no normalised
	// version under the 'unknown' scheme).
	gatewayRows, err := lister.ListByVendorProductNorm(ctx, "acme", "gateway")
	if err != nil || len(gatewayRows) != 1 || gatewayRows[0].ID != demoUUID(gatewayID) {
		t.Fatalf("ListByVendorProductNorm (acme/gateway) = %+v, %v; want exactly the gateway component", gatewayRows, err)
	}
	gw := gatewayRows[0]
	if gw.CPE != "" || gw.PURL != "" || gw.Image != "" || gw.Digest != "" {
		t.Fatalf("gateway row identifiers = %q/%q/%q/%q, want all empty (NULL)", gw.CPE, gw.PURL, gw.Image, gw.Digest)
	}
	if gw.VersionNorm != "" {
		t.Fatalf("gateway row version_norm = %q, want empty ('unknown' normalises nothing)", gw.VersionNorm)
	}
	if gw.VersionScheme != domain.VersionSchemeUnknown {
		t.Fatalf("gateway row version_scheme = %q, want unknown", gw.VersionScheme)
	}
	if gw.NaturalKey != gatewayKey {
		t.Fatalf("gateway row natural_key = %q, want the derived %q", gw.NaturalKey, gatewayKey)
	}
}
