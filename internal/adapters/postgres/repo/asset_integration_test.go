package repo

// Integration test for the WP-5b.02 schema + read paths (ARCH-006 §2.1/§2.2,
// DEV-098): the inventory_imports staging lifecycle (migration 00010 —
// store → read → commit-mark, with the guarded re-commit a no-op) and the
// AssetRepo read queries (ListAssets with the owner_id object-scope filter;
// GetAssetComponents returning one asset and its ordered components).
//
// It runs against a real, short-lived PostgreSQL database created per test
// case and migrated with the embedded migration set (the shared
// newI4TestPool helper of i4_integration_test.go, same package; it therefore
// also proves migration 00010 applies cleanly to a fresh database). When no
// database is reachable the test skips, so `go test ./...` stays green on
// machines without the environment.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// TestInventoryImportsStagingIntegration exercises the staged import record
// over the generated queries: insert (pending), read-back, the guarded
// commit-mark and the idempotent re-commit, plus the operator list.
func TestInventoryImportsStagingIntegration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q := gen.New(pool)

	now := time.Now().UTC().Truncate(time.Microsecond)
	file := []byte("source,external_id,type,name,environment,criticality,exposure\ninv,a1,server_vm,Alpha,production,critical,internet\n")

	// 1. Store a staged upload in status 'pending'.
	inserted, err := q.InsertInventoryImport(ctx, gen.InsertInventoryImportParams{
		Status:        "pending",
		File:          file,
		Rows:          1,
		ErrorCount:    0,
		WarningCount:  1,
		ActorID:       "actor-1",
		CorrelationID: toTextOpt("corr-1"),
		CreatedAt:     toTS(now),
	})
	if err != nil {
		t.Fatalf("insert inventory import: %v", err)
	}
	importID := uuidString(inserted.ID)
	if importID == "" {
		t.Fatal("insert returned an empty id")
	}
	if inserted.Status != "pending" {
		t.Fatalf("inserted status = %q, want pending", inserted.Status)
	}
	if string(inserted.File) != string(file) {
		t.Fatalf("stored file = %q, want the uploaded bytes back verbatim", inserted.File)
	}
	if inserted.CommittedAt.Valid {
		t.Fatalf("committed_at on a pending record = %v, want NULL", inserted.CommittedAt)
	}
	if inserted.AssetsCreated != 0 || inserted.ComponentsUpdated != 0 {
		t.Fatalf("commit-outcome counters default = %d/%d, want 0/0", inserted.AssetsCreated, inserted.ComponentsUpdated)
	}

	// 2. Read it back by id.
	got, err := q.GetInventoryImport(ctx, inserted.ID)
	if err != nil {
		t.Fatalf("get inventory import: %v", err)
	}
	if got.Status != "pending" || got.Rows != 1 || got.WarningCount != 1 {
		t.Fatalf("read-back = %+v, want the stored pending record", got)
	}
	if !got.CorrelationID.Valid || got.CorrelationID.String != "corr-1" {
		t.Fatalf("read-back correlation_id = %v, want corr-1", got.CorrelationID)
	}

	// 3. Commit-mark it: pending → committed, committed_at stamped.
	committedAt := now.Add(10 * time.Minute)
	marked, err := q.MarkInventoryImportCommitted(ctx, gen.MarkInventoryImportCommittedParams{
		Now: toTS(committedAt),
		ID:  inserted.ID,
	})
	if err != nil {
		t.Fatalf("mark committed: %v", err)
	}
	if marked.Status != "committed" {
		t.Fatalf("marked status = %q, want committed", marked.Status)
	}
	if !marked.CommittedAt.Valid || !marked.CommittedAt.Time.Equal(committedAt) {
		t.Fatalf("committed_at = %v, want %v", marked.CommittedAt, committedAt)
	}

	// 4. Re-commit is a no-op: the pending guard matches zero rows, so the
	// statement reports no row (pgx.ErrNoRows) and never re-stamps the record.
	if _, err := q.MarkInventoryImportCommitted(ctx, gen.MarkInventoryImportCommittedParams{
		Now: toTS(committedAt.Add(time.Hour)),
		ID:  inserted.ID,
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second commit err = %v, want pgx.ErrNoRows (guard did not match)", err)
	}
	reread, err := q.GetInventoryImport(ctx, inserted.ID)
	if err != nil {
		t.Fatalf("get after re-commit: %v", err)
	}
	if !reread.CommittedAt.Time.Equal(committedAt) {
		t.Fatalf("committed_at moved on re-commit: %v → %v", committedAt, reread.CommittedAt.Time)
	}

	// 5. An unknown import id is not-found.
	if _, err := q.GetInventoryImport(ctx, toMustUUID(t, "00000000-0000-4000-8000-0000000000ff")); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("get unknown import err = %v, want pgx.ErrNoRows", err)
	}

	// 6. The operator list returns the record.
	list, err := q.ListInventoryImports(ctx)
	if err != nil {
		t.Fatalf("list inventory imports: %v", err)
	}
	found := false
	for _, r := range list {
		if uuidString(r.ID) == importID {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListInventoryImports did not include the stored import %s", importID)
	}
}

// TestAssetReadIntegration exercises the AssetRepo read queries: the
// owner_id-filtered list and the one-asset-with-components read.
func TestAssetReadIntegration(t *testing.T) {
	pool := newI4TestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	assets := NewAssetRepo(gen.New(pool))

	base := time.Now().UTC().Truncate(time.Microsecond)

	// Seed three assets: two owned by different principals, one unowned.
	seedAsset := func(t *testing.T, externalID, typ, name, owner string, createdAt time.Time) string {
		t.Helper()
		var id pgtype.UUID
		ownerArg := pgtype.Text{}
		if owner != "" {
			ownerArg = pgtype.Text{String: owner, Valid: true}
		}
		if err := pool.QueryRow(ctx, `
			INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure, owner, created_at, updated_at)
			VALUES ($1, 'inv', $2, $3, 'production', 'critical', 'internet', $4, $5, $5)
			RETURNING id`,
			externalID, typ, name, ownerArg, createdAt).Scan(&id); err != nil {
			t.Fatalf("seed asset %s: %v", externalID, err)
		}
		return uuidString(id)
	}

	alphaID := seedAsset(t, "alpha", "server_vm", "Alpha", "owner-1", base)
	_ = seedAsset(t, "beta", "container_image", "Beta", "owner-2", base.Add(time.Minute))
	_ = seedAsset(t, "gamma", "cloud_saas", "Gamma", "", base.Add(2*time.Minute))

	// Alpha carries two components; order by natural_key is key-a then key-b.
	if _, err := pool.Exec(ctx, `
		INSERT INTO components (asset_id, vendor, product, version, vendor_norm, product_norm, version_scheme, natural_key)
		VALUES ($1, 'acme', 'widget', '1.0', 'acme', 'widget', 'semver', 'key-b'),
		       ($1, 'acme', 'gadget', '2.0', 'acme', 'gadget', 'semver', 'key-a')`, alphaID); err != nil {
		t.Fatalf("seed components: %v", err)
	}

	// 1. The owner_id filter returns only the owned rows (the object-scope
	// injection point of an `assigned`/`own` inventory.read grant).
	owner1 := "owner-1"
	owned, err := assets.ListAssets(ctx, application.AssetFilter{OwnerID: &owner1}, 10, 0)
	if err != nil {
		t.Fatalf("list assets by owner: %v", err)
	}
	if len(owned) != 1 || owned[0].ID != alphaID {
		t.Fatalf("owner_id=owner-1 filter returned %d rows (%+v), want only Alpha", len(owned), owned)
	}
	if owned[0].Type != "server_vm" || owned[0].Name != "Alpha" || owned[0].Owner != "owner-1" {
		t.Fatalf("owned asset = %+v, want Alpha/owner-1", owned[0])
	}

	// 2. No filter returns all three, ordered by created_at then id.
	all, err := assets.ListAssets(ctx, application.AssetFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("list all assets: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("unfiltered list = %d rows, want 3", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].CreatedAt.After(all[i].CreatedAt) {
			t.Fatalf("assets not ordered by created_at: %v before %v", all[i-1].CreatedAt, all[i].CreatedAt)
		}
	}

	// 3. A second filter (type) narrows the read like the first.
	serverVM := application.AssetFilter{Type: ptrDomain(domain.AssetType("server_vm"))}
	byType, err := assets.ListAssets(ctx, serverVM, 10, 0)
	if err != nil {
		t.Fatalf("list assets by type: %v", err)
	}
	if len(byType) != 1 || byType[0].Name != "Alpha" {
		t.Fatalf("type=server_vm filter = %+v, want only Alpha", byType)
	}

	// 4. GetAssetComponents returns the asset plus its components ordered by
	// natural_key.
	detail, err := assets.GetAssetComponents(ctx, alphaID)
	if err != nil {
		t.Fatalf("get asset components: %v", err)
	}
	if detail.Asset.ID != alphaID || detail.Asset.Name != "Alpha" {
		t.Fatalf("asset = %+v, want Alpha", detail.Asset)
	}
	if len(detail.Components) != 2 {
		t.Fatalf("components = %d, want 2", len(detail.Components))
	}
	if detail.Components[0].Product != "gadget" || detail.Components[1].Product != "widget" {
		t.Fatalf("components = [%s %s], want [gadget widget] (ordered by natural_key)",
			detail.Components[0].Product, detail.Components[1].Product)
	}
	if detail.Components[0].AssetID != alphaID || detail.Components[0].NaturalKey != "key-a" {
		t.Fatalf("first component = %+v, want asset %s natural key key-a", detail.Components[0], alphaID)
	}

	// 5. An asset without components returns the asset and an empty slice.
	gamma, err := assets.ListAssets(ctx, application.AssetFilter{Source: ptrString("inv")}, 10, 2)
	if err != nil {
		t.Fatalf("list page two: %v", err)
	}
	if len(gamma) != 1 || gamma[0].Name != "Gamma" {
		t.Fatalf("offset page = %+v, want only Gamma", gamma)
	}
	gammaDetail, err := assets.GetAssetComponents(ctx, gamma[0].ID)
	if err != nil {
		t.Fatalf("get component-less asset: %v", err)
	}
	if len(gammaDetail.Components) != 0 {
		t.Fatalf("component-less asset components = %d, want 0", len(gammaDetail.Components))
	}

	// 6. An unknown asset id is a not-found error.
	if _, err := assets.GetAssetComponents(ctx, "00000000-0000-4000-8000-0000000000ff"); err == nil {
		t.Fatal("GetAssetComponents on an unknown id succeeded, want not-found")
	} else {
		var appErr *application.Error
		if !errors.As(err, &appErr) || appErr.Kind != application.KindNotFound {
			t.Fatalf("unknown-asset error = %v, want a not-found application error", err)
		}
	}
}

func ptrString(s string) *string { return &s }

func ptrDomain[T any](v T) *T { return &v }

func toMustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	u, err := toUUID(s)
	if err != nil {
		t.Fatalf("toUUID(%q): %v", s, err)
	}
	return u
}
