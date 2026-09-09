package main

// Integration test of the WP-3.02 migration 00005 at the composition root
// (DEV-045): the I3 inventory & matching extensions must land on top of the
// I1b/I2 schema without breaking the pre-I3 rows. cmd/risksignal is the
// composition root that may wire the embedded migration set (db/migrations)
// together with the runner, so the real files are exercised here.
//
// The test migrates a scratch database up to 00004 (the I2 schema, applied
// from the real embedded files), seeds I1b-shaped rows exactly like the
// pre-I3 demo does (an asset, two vendor/product/version components, a
// vulnerability and one match), applies the remaining embedded migration
// (00005) and asserts the extension surface of ARCH-003 §1.1/§1.2/§1.4/§3/
// §4/§7:
//
//   - assets carry updated_at/deactivated_at/verified_at and keep
//     UQ (source, external_id);
//   - the legacy components were backfilled with safe defaults (comparison
//     keys, version_scheme 'unknown', a deterministic 'legacy:' natural
//     key) and the new schema locks them in: NOT NULL comparison keys and
//     natural key, UQ (asset_id, natural_key), the inventory product index
//     (vendor_norm, product_norm) replacing the I1b (vendor, product)
//     index, IX (asset_id), the identifier CHECK — image included (DEV-044
//     reconciliation) — and the 7-value version_scheme CHECK;
//   - alias_rules/decision_rules exist per ARCH-003 §1.4 with their
//     versioning UQ/columns;
//   - the seeded match survived with reasons '[]', the auto_* triple NULL,
//     and matches carries the decision_rule_id FK while keeping
//     UQ (vulnerability_id, component_id, rule_version);
//   - epss_history exists append-only with UQ (cve_id, observed_on) and no
//     foreign key onto epss_current (ADR-013);
//   - the identifier/version_scheme CHECKs enforce: image-only rows are
//     valid, identifier-less rows and unknown schemes are rejected, and
//     the pre-I3 component insert shape (no comparison keys) is rejected —
//     the schema is I3-shaped from 00005 on (DEV-046 regenerates the
//     component queries).
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

// constraintDef returns the pg_get_constraintdef text of the named
// constraint on table, or "" when the constraint does not exist.
func constraintDef(t *testing.T, ctx context.Context, db *sql.DB, table, constraint string) string {
	t.Helper()
	var def sql.NullString
	if err := db.QueryRowContext(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = $1::regclass AND conname = $2`, table, constraint).Scan(&def); err != nil {
		if err == sql.ErrNoRows {
			return ""
		}
		t.Fatalf("constraintDef(%s.%s): %v", table, constraint, err)
	}
	return def.String
}

// columnNullable reports whether the named column is nullable.
func columnNullable(t *testing.T, ctx context.Context, db *sql.DB, table, column string) bool {
	t.Helper()
	var nullable string
	if err := db.QueryRowContext(ctx, `
		SELECT is_nullable FROM information_schema.columns
		WHERE table_name = $1 AND column_name = $2`, table, column).Scan(&nullable); err != nil {
		t.Fatalf("columnNullable(%s.%s): %v", table, column, err)
	}
	return nullable == "YES"
}

func TestMigration00005ExtendsInventoryAndMatchingSchema(t *testing.T) {
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

	// Step 2: seed I1b-shaped rows exactly like the pre-I3 demo chain: one
	// asset, two vendor/product/version components, one vulnerability and
	// one match row (I1b columns only — the shapes 00005 must extend).
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
	var componentPortal, componentAPI string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version)
		VALUES ($1::uuid, 'acme', 'portal', '2.4.4')
		RETURNING id::text`, assetID).Scan(&componentPortal); err != nil {
		t.Fatalf("seed component portal: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version)
		VALUES ($1::uuid, 'acme', 'api', '1.0')
		RETURNING id::text`, assetID).Scan(&componentAPI); err != nil {
		t.Fatalf("seed component api: %v", err)
	}
	var vulnID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO vulnerabilities (cve_id, summary, published_at)
		VALUES ('CVE-2024-9002', 'legacy summary', now())
		RETURNING id::text`).Scan(&vulnID); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO matches (vulnerability_id, component_id, method, score, confidence, rule_version, created_at)
		VALUES ($1::uuid, $2::uuid, 'exact_identifier', 100, 'high', 'i1b-1', now())`, vulnID, componentPortal); err != nil {
		t.Fatalf("seed match: %v", err)
	}

	// Step 3: apply migration 00005 on top of the I2 schema (pinned to
	// version 5 — later embedded migrations stay out of this test's scope)
	// and prove the checksum log records it; a second run is a no-op.
	runner, err = migrate.Open(ctx, dbURL, migrationFSUpTo(t, 5))
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer runner.Close()
	res, err := runner.Migrate(ctx, false)
	if err != nil {
		t.Fatalf("apply 00005: %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].Version != 5 {
		t.Fatalf("applied = %+v, want exactly version 5", res.Applied)
	}
	if res, err := runner.Migrate(ctx, false); err != nil || len(res.Applied) != 0 {
		t.Fatalf("rerun after 00005 = %+v, %v; want a no-op", res, err)
	}

	// Step 4: assert the ARCH-003 extension surface.

	// --- assets (ARCH-003 §1.1): lifecycle columns, UQ unchanged ---------
	if columnNullable(t, ctx, db, "assets", "updated_at") {
		t.Fatal("assets.updated_at must be NOT NULL")
	}
	for _, col := range []string{"deactivated_at", "verified_at"} {
		if !columnNullable(t, ctx, db, "assets", col) {
			t.Fatalf("assets.%s must be nullable", col)
		}
	}
	if def := constraintDef(t, ctx, db, "assets", "assets_source_external_id_key"); !strings.HasPrefix(def, "UNIQUE (source, external_id)") {
		t.Fatalf("assets UQ (source, external_id) = %q, want it preserved", def)
	}

	// --- components (ARCH-003 §1.2/§1.3/§4) ------------------------------
	// Legacy rows were backfilled with safe defaults: comparison keys are
	// the trim+lowercase fold of the originals, version_scheme 'unknown'
	// and the natural key is a deterministic 'legacy:' placeholder.
	var vendorNorm, productNorm, scheme, naturalKey string
	var updatedAtSet bool
	if err := db.QueryRowContext(ctx, `
		SELECT vendor_norm, product_norm, version_scheme, natural_key, updated_at IS NOT NULL
		FROM components WHERE id = $1::uuid`, componentPortal).Scan(&vendorNorm, &productNorm, &scheme, &naturalKey, &updatedAtSet); err != nil {
		t.Fatalf("read backfilled component: %v", err)
	}
	if vendorNorm != "acme" || productNorm != "portal" || scheme != "unknown" {
		t.Fatalf("backfill = vendor_norm %q product_norm %q scheme %q, want acme/portal/unknown", vendorNorm, productNorm, scheme)
	}
	if !strings.HasPrefix(naturalKey, "legacy:") || len(naturalKey) != len("legacy:")+32 {
		t.Fatalf("natural_key = %q, want a 'legacy:' md5 placeholder", naturalKey)
	}
	if !updatedAtSet {
		t.Fatal("backfilled component must carry an updated_at")
	}
	// The natural keys of the two legacy components differ (identity keys).
	var otherKey string
	if err := db.QueryRowContext(ctx, `SELECT natural_key FROM components WHERE id = $1::uuid`, componentAPI).Scan(&otherKey); err != nil {
		t.Fatalf("read second backfilled component: %v", err)
	}
	if otherKey == naturalKey {
		t.Fatal("two distinct legacy components must not share a natural key")
	}

	// New columns: identifier originals nullable, keys locked NOT NULL.
	for _, col := range []string{"cpe", "purl", "image", "digest", "version_norm", "deactivated_at"} {
		if !columnNullable(t, ctx, db, "components", col) {
			t.Fatalf("components.%s must be nullable", col)
		}
	}
	for _, col := range []string{"vendor_norm", "product_norm", "natural_key", "version_scheme", "updated_at"} {
		if columnNullable(t, ctx, db, "components", col) {
			t.Fatalf("components.%s must be NOT NULL", col)
		}
	}

	// Constraints and indexes: import idempotency UQ, identifier CHECK with
	// image (DEV-044 reconciliation), 7-value version_scheme CHECK, product
	// index replacing the I1b (vendor, product) index, asset_id index.
	if def := constraintDef(t, ctx, db, "components", "components_asset_id_natural_key_key"); !strings.HasPrefix(def, "UNIQUE (asset_id, natural_key)") {
		t.Fatalf("components UQ = %q, want UNIQUE (asset_id, natural_key)", def)
	}
	identDef := constraintDef(t, ctx, db, "components", "components_identifier_check")
	if !strings.Contains(identDef, "image IS NOT NULL") {
		t.Fatalf("components_identifier_check = %q, want image included", identDef)
	}
	if !strings.Contains(identDef, "vendor_norm <> ''") || !strings.Contains(identDef, "product_norm <> ''") {
		t.Fatalf("components_identifier_check = %q, want the vendor_norm/product_norm pair branch", identDef)
	}
	schemeDef := constraintDef(t, ctx, db, "components", "components_version_scheme_check")
	for _, v := range []string{"semver", "debian", "rpm", "maven", "calver", "generic", "unknown"} {
		if !strings.Contains(schemeDef, "'"+v+"'") {
			t.Fatalf("components_version_scheme_check = %q, missing %s (want all 7 values)", schemeDef, v)
		}
	}
	for idx, cols := range map[string]string{
		"components_product_idx":  "vendor_norm, product_norm",
		"components_asset_id_idx": "asset_id",
	} {
		var def string
		if err := db.QueryRowContext(ctx,
			"SELECT indexdef FROM pg_indexes WHERE tablename = 'components' AND indexname = $1", idx).Scan(&def); err != nil {
			t.Fatalf("index %s missing: %v", idx, err)
		}
		if !strings.Contains(def, "("+cols+")") {
			t.Fatalf("index %s = %q, want on (%s)", idx, def, cols)
		}
	}
	var legacyIdx *string
	if err := db.QueryRowContext(ctx, "SELECT to_regclass('components_vendor_product_idx')").Scan(&legacyIdx); err != nil {
		t.Fatalf("check legacy index: %v", err)
	}
	if legacyIdx != nil {
		t.Fatal("I1b index components_vendor_product_idx must be gone (replaced by the product index)")
	}

	// CHECK enforcement: an image-only component is valid (image is an
	// identifier), an identifier-less row and an unknown version_scheme are
	// rejected, and the pre-I3 insert shape (no comparison keys) is
	// rejected — rows are I3-shaped from 00005 on (DEV-046 regenerates the
	// component queries for the new required columns).
	if _, err := db.ExecContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version, image, vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1::uuid, '', '', '', 'registry.example.com/acme/portal@sha256:abcdef', '', '', 'unknown', 'probe-image-only')`, assetID); err != nil {
		t.Fatalf("image-only component must be accepted (image is an identifier): %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1::uuid, '', '', '', '', '', 'unknown', 'probe-no-identifier')`, assetID); err == nil {
		t.Fatal("identifier-less component must be rejected by components_identifier_check")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1::uuid, 'x', 'y', '1', 'x', 'y', 'fancy', 'probe-bad-scheme')`, assetID); err == nil {
		t.Fatal("unknown version_scheme must be rejected by components_version_scheme_check")
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO components (asset_id, vendor, product, version)
		VALUES ($1::uuid, 'acme', 'portal', '9.9')`, assetID); err == nil {
		t.Fatal("pre-I3 component insert shape (no comparison keys) must be rejected after 00005")
	}

	// --- alias_rules / decision_rules (ARCH-003 §1.4) --------------------
	for _, table := range []string{"alias_rules", "decision_rules"} {
		var reg *string
		if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)", table).Scan(&reg); err != nil {
			t.Fatalf("to_regclass(%s): %v", table, err)
		}
		if reg == nil {
			t.Fatalf("table %s missing after 00005", table)
		}
	}
	if def := constraintDef(t, ctx, db, "alias_rules", "alias_rules_scope_from_value_version_key"); !strings.HasPrefix(def, "UNIQUE (scope, from_value, version)") {
		t.Fatalf("alias_rules UQ = %q, want UNIQUE (scope, from_value, version)", def)
	}
	for _, col := range []string{"valid_from", "valid_until", "revoked_at", "action"} {
		if !columnNullable(t, ctx, db, "decision_rules", col) {
			t.Fatalf("decision_rules.%s must be nullable", col)
		}
	}
	if def := constraintDef(t, ctx, db, "decision_rules", "decision_rules_type_check"); !strings.Contains(def, "'exclude'") || !strings.Contains(def, "'override'") {
		t.Fatalf("decision_rules_type_check = %q, want exclude | override", def)
	}

	// --- matches (ARCH-003 §3) -------------------------------------------
	// The pre-I3 match row survived with the new defaults: reasons '[]',
	// no decision rule, no auto_* triple — while UQ (vulnerability_id,
	// component_id, rule_version) is preserved for idempotent re-runs.
	var reasons string
	var autoMethod, autoConfidence sql.NullString
	var autoScore sql.NullInt64
	if err := db.QueryRowContext(ctx, `
		SELECT reasons::text, auto_method, auto_confidence, auto_score
		FROM matches WHERE component_id = $1::uuid AND vulnerability_id = $2::uuid`,
		componentPortal, vulnID).Scan(&reasons, &autoMethod, &autoConfidence, &autoScore); err != nil {
		t.Fatalf("read pre-I3 match: %v", err)
	}
	if reasons != "[]" {
		t.Fatalf("pre-I3 match reasons = %q, want the '[]' default", reasons)
	}
	if autoMethod.Valid || autoConfidence.Valid || autoScore.Valid {
		t.Fatalf("pre-I3 match auto_* triple = %v/%v/%v, want all NULL", autoMethod, autoConfidence, autoScore)
	}
	if def := constraintDef(t, ctx, db, "matches", "matches_decision_rule_id_fkey"); !strings.Contains(def, "REFERENCES decision_rules(id)") {
		t.Fatalf("matches decision_rule_id FK = %q, want REFERENCES decision_rules(id)", def)
	}
	if def := constraintDef(t, ctx, db, "matches", "matches_vulnerability_id_component_id_rule_version_key"); !strings.HasPrefix(def, "UNIQUE (vulnerability_id, component_id, rule_version)") {
		t.Fatalf("matches UQ = %q, want it preserved", def)
	}

	// --- epss_history (ARCH-003 §7, ADR-013) -----------------------------
	for _, col := range []string{"cve_id", "observed_on", "score", "percentile", "model_version"} {
		if columnNullable(t, ctx, db, "epss_history", col) {
			t.Fatalf("epss_history.%s must be NOT NULL", col)
		}
	}
	if def := constraintDef(t, ctx, db, "epss_history", "epss_history_cve_id_observed_on_key"); !strings.HasPrefix(def, "UNIQUE (cve_id, observed_on)") {
		t.Fatalf("epss_history UQ = %q, want UNIQUE (cve_id, observed_on)", def)
	}
	// Append-only and unfettered: no foreign key anywhere on epss_history
	// (ADR-013 — in particular none onto epss_current).
	var fkCount int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM pg_constraint
		WHERE conrelid = 'epss_history'::regclass AND contype = 'f'`).Scan(&fkCount); err != nil {
		t.Fatalf("count epss_history foreign keys: %v", err)
	}
	if fkCount != 0 {
		t.Fatalf("epss_history carries %d foreign key(s), want none (ADR-013)", fkCount)
	}
}
