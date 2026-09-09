package main

// Integration test of the WP-3.03b Contract phase (DEV-057, ARCH-003
// §1.2/§1.3, implementation concept ch. 7.4 Expand-Migrate-Contract): the
// component write path is switched (DEV-056/DEV-058) and migration 00006
// now contracts what migration 00005 (Expand phase) left nullable.
// cmd/risksignal is the composition root that may wire the embedded
// migration set (db/migrations) together with the runner, so the real
// files are exercised here.
//
// The test migrates a scratch database up to 00005 (migrationFSUpTo),
// seeds the two row shapes an existing pre-contract database can hold —
// legacy I1b rows backfilled by 00005 with safe defaults ('legacy:' md5
// keys) and rows written through the I3 write path after the DEV-056
// switch (comparison keys + derived natural key set) — and applies the
// remaining embedded migration (00006). It then asserts the contract
// surface:
//
//   - vendor_norm / product_norm / natural_key are NOT NULL — the
//     backfilled legacy rows and the I3-path rows both survive the
//     SET NOT NULL, and a pre-I3 4-column insert (the 00005 Expand-phase
//     shape) is now rejected loudly instead of landing a row that cannot
//     participate in UQ (asset_id, natural_key) or the product index;
//   - components_identifier_check exists with every identifier branch
//     trimmed-then-non-empty (btrim(col) <> '') — cpe, purl, digest and
//     image (image included per the DEV-044 reconciliation) plus the
//     vendor_norm/product_norm pair — mirroring the domain presence rule
//     hasAnyIdentifier (component.go): a whitespace-only comparison-key
//     pair carries no identity and is rejected, while an image-only row
//     is matchable and accepted;
//   - rerunning the migration is a no-op and the checksum log records
//     version 6.
//
// The database server is the compose `db` service (make up) or any other
// PostgreSQL reachable through RISKSIGNAL_TEST_DATABASE_URL; when none is
// reachable the test skips (newTestDB), so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xpera/risksignal/internal/adapters/postgres/migrate"
)

func TestMigration00006ContractsTheComponentWritePath(t *testing.T) {
	dbURL := newTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: apply the real I2 schema (00001..00004).
	runner, err := migrate.Open(ctx, dbURL, migrationFSUpTo(t, 4))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 4 {
		t.Fatalf("apply I2 migrations: res=%+v err=%v", res, err)
	}
	_ = runner.Close()

	// Step 2: seed I1b-shaped rows exactly like the pre-I3 demo chain (the
	// shapes 00005 backfills): one asset and two vendor/product/version
	// components whose comparison keys and natural_key are still NULL.
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	var assetID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure, owner)
		VALUES ('asset-legacy', 'demo', 'server_vm', 'Legacy Portal', 'production', 'critical', 'internet', NULL)
		RETURNING id::text`).Scan(&assetID); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	var legacyPortal, legacyAPI string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version)
		VALUES ($1::uuid, 'acme', 'portal', '2.4.4')
		RETURNING id::text`, assetID).Scan(&legacyPortal); err != nil {
		t.Fatalf("seed component portal: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version)
		VALUES ($1::uuid, 'acme', 'api', '1.0')
		RETURNING id::text`, assetID).Scan(&legacyAPI); err != nil {
		t.Fatalf("seed component api: %v", err)
	}

	// Step 3: apply migration 00005 (Expand phase) — the legacy rows are
	// backfilled with comparison keys, version_scheme 'unknown' and a
	// deterministic 'legacy:' natural key — then write one row through the
	// switched I3 path (DEV-056/DEV-058): comparison keys and the derived
	// natural key set, exactly like InsertComponent (db/queries/
	// components.sql) writes it. Both shapes are what an existing database
	// carries when 00006 arrives.
	runner, err = migrate.Open(ctx, dbURL, migrationFSUpTo(t, 5))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		_ = runner.Close()
		t.Fatalf("apply 00005: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close after 00005: %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].Version != 5 {
		t.Fatalf("applied = %+v, want exactly version 5", res.Applied)
	}

	var i3Component string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version,
		                        vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1::uuid, 'Acme', 'Gateway', '1.0', 'acme', 'gateway', 'unknown', 'i3-path-key-gateway')
		RETURNING id::text`, assetID).Scan(&i3Component); err != nil {
		t.Fatalf("seed I3-path component: %v", err)
	}

	// Step 4: apply migration 00006 on top (pinned to version 6 — later
	// embedded migrations stay out of scope) and prove the checksum log
	// records it; a second run is a no-op. The legacy backfilled rows and
	// the I3-path row both survive the SET NOT NULL.
	runner, err = migrate.Open(ctx, dbURL, migrationFSUpTo(t, 6))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer runner.Close()
	res, err = runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("apply 00006: %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].Version != 6 {
		t.Fatalf("applied = %+v, want exactly version 6", res.Applied)
	}
	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 0 {
		t.Fatalf("rerun after 00006 = %+v, %v; want a no-op", res, err)
	}

	// Step 5: assert the contract surface.

	// --- NOT NULL on the comparison keys and the natural key -------------
	for _, col := range []string{"vendor_norm", "product_norm", "natural_key"} {
		if columnNullable(t, ctx, db, "components", col) {
			t.Fatalf("components.%s must be NOT NULL after the 00006 contract phase", col)
		}
	}
	// The nullable columns of the Expand phase stay nullable (the
	// identifier originals, version_norm, lifecycle): 00006 only contracts
	// the comparison keys and the natural key.
	for _, col := range []string{"cpe", "purl", "image", "digest", "version_norm", "deactivated_at"} {
		if !columnNullable(t, ctx, db, "components", col) {
			t.Fatalf("components.%s must stay nullable after 00006", col)
		}
	}

	// --- both pre-contract row shapes survived ----------------------------
	var vn, pn, nk string
	if err := db.QueryRowContext(ctx, `
		SELECT vendor_norm, product_norm, natural_key FROM components WHERE id = $1::uuid`,
		legacyPortal).Scan(&vn, &pn, &nk); err != nil {
		t.Fatalf("read backfilled legacy component: %v", err)
	}
	if vn != "acme" || pn != "portal" || !strings.HasPrefix(nk, "legacy:") {
		t.Fatalf("legacy component after 00006 = vendor_norm %q product_norm %q natural_key %q, want acme/portal/legacy:…", vn, pn, nk)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT vendor_norm, product_norm, natural_key FROM components WHERE id = $1::uuid`,
		i3Component).Scan(&vn, &pn, &nk); err != nil {
		t.Fatalf("read I3-path component: %v", err)
	}
	if vn != "acme" || pn != "gateway" || nk != "i3-path-key-gateway" {
		t.Fatalf("I3-path component after 00006 = vendor_norm %q product_norm %q natural_key %q, want acme/gateway/i3-path-key-gateway", vn, pn, nk)
	}

	// --- components_identifier_check: trim-then-non-empty branches, image
	// included (DEV-044 reconciliation) -----------------------------------
	def := constraintDef(t, ctx, db, "components", "components_identifier_check")
	for _, branch := range []string{"btrim(cpe)", "btrim(purl)", "btrim(digest)", "btrim(image)", "btrim(vendor_norm)", "btrim(product_norm)"} {
		if !strings.Contains(def, branch) {
			t.Fatalf("components_identifier_check = %q, missing the %s branch (all branches must be trim-then-non-empty)", def, branch)
		}
	}
	if !strings.Contains(strings.ToLower(def), "coalesce") || !strings.Contains(def, "<> ''::text") {
		t.Fatalf("components_identifier_check = %q, want COALESCE(btrim(col), '') <> '' branches (trim-then-non-empty, NULL-safe)", def)
	}

	// --- contract enforcement ---------------------------------------------
	// The pre-I3 4-column InsertComponent shape (the 00005 Expand-phase
	// write, db/queries/components.sql header) is rejected: it would land a
	// row with NULL comparison keys and NULL natural key.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version)
		VALUES ($1::uuid, 'acme', 'tool', '1.2.3')`, assetID); err == nil {
		t.Fatal("pre-I3 4-column insert must be rejected after the 00006 contract phase (NULL keys)")
	}
	// A comparison-key pair of whitespace only carries no identity: the
	// trimmed-then-non-empty branches reject it even though the keys are
	// present (NOT NULL) — whitespace is not matchable (domain
	// hasAnyIdentifier).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version,
		                        vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1::uuid, '', '', '1', '   ', '  ', 'unknown', 'blank-keys-row')`, assetID); err == nil {
		t.Fatal("whitespace-only comparison keys must be rejected by components_identifier_check")
	}
	// An image-only row is matchable and accepted: image is a standalone
	// identity branch of the CHECK (DEV-044 reconciliation — the domain
	// treats an image-only component as valid), so a row whose comparison
	// keys are empty passes on btrim(image) <> ''.
	var imageOnly string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version, image,
		                        vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1::uuid, '', '', '', 'registry.acme.test/app:1.2.3', '', '', 'unknown', 'image-only-key')
		RETURNING id::text`, assetID).Scan(&imageOnly); err != nil {
		t.Fatalf("image-only component must be accepted by components_identifier_check: %v", err)
	}
	var img string
	if err := db.QueryRowContext(ctx, `SELECT image FROM components WHERE id = $1::uuid`, imageOnly).Scan(&img); err != nil {
		t.Fatalf("read image-only component: %v", err)
	}
	if img != "registry.acme.test/app:1.2.3" {
		t.Fatalf("image-only component image = %q, want the original preserved verbatim", img)
	}
	// A purl-only row is likewise accepted on its own branch.
	var purlOnly string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version, purl,
		                        vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1::uuid, '', '', '', 'pkg:deb/debian/curl@7.0', '', '', 'debian', 'purl-only-key')
		RETURNING id::text`, assetID).Scan(&purlOnly); err != nil {
		t.Fatalf("purl-only component must be accepted by components_identifier_check: %v", err)
	}
	_ = purlOnly
}
