package application_test

// Unit tests of the I5b asset read use cases (WP-5b.03 / DEV-099, ARCH-006
// §2.2): ListAssets and GetAssetComponents — the permission gate and the
// deny-by-default object scope (an `assigned` inventory.read grant injects
// owner_id = principal.id), the filters/cursor, and the not-found path. All
// run against the in-memory fakes; no database.

import (
	"context"
	"testing"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// seedAsset appends one committed asset to the fake database.
func seedAsset(h *harness, id, source, external, typ, name, env, crit, exposure, owner string) {
	h.db.assets = append(h.db.assets, fakeStoredAsset{
		id:          id,
		source:      source,
		externalID:  external,
		typ:         typ,
		name:        name,
		environment: env,
		criticality: crit,
		exposure:    exposure,
		owner:       owner,
		updatedAt:   fixedNow,
	})
}

func TestListAssetsObjectScopeInjectsOwnerFilter(t *testing.T) {
	h := newHarness(t)
	seedAsset(h, "a1", "cmdb", "e1", "server_vm", "one", "production", "high", "internet", "u-sys")
	seedAsset(h, "a2", "cmdb", "e2", "server_vm", "two", "production", "high", "internet", "u-other")
	seedAsset(h, "a3", "cmdb", "e3", "server_vm", "three", "production", "high", "internet", "")
	// The Systemverantwortliche holds inventory.read at the assigned scope.
	h.users.add("u-sys", "Sys", domain.RoleSystemResponsible)
	// An explicit owner filter pointing at another principal must not widen
	// the scoped read.
	other := "u-other"

	res, err := h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("u-sys"), OwnerID: &other})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(res.Assets) != 1 || res.Assets[0].ID != "a1" {
		t.Fatalf("scoped read = %d assets (%v), want only a1", len(res.Assets), res.Assets)
	}
}

func TestListAssetsAdminSeesAllAndFilters(t *testing.T) {
	h := newHarness(t)
	seedAsset(h, "a1", "cmdb", "e1", "server_vm", "one", "production", "high", "internet", "u-other")
	seedAsset(h, "a2", "cmdb", "e2", "container_image", "two", "staging", "low", "internal", "")
	h.users.add("admin", "Admin", domain.RoleAdministrator)

	res, err := h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("admin")})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(res.Assets) != 2 {
		t.Fatalf("admin read = %d assets, want 2", len(res.Assets))
	}

	typ := domain.AssetTypeContainerImage
	res, err = h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("admin"), Type: &typ})
	if err != nil {
		t.Fatalf("ListAssets(type): %v", err)
	}
	if len(res.Assets) != 1 || res.Assets[0].ID != "a2" {
		t.Fatalf("type filter = %v, want only a2", res.Assets)
	}
}

func TestListAssetsCursorPaginates(t *testing.T) {
	h := newHarness(t)
	seedAsset(h, "a1", "cmdb", "e1", "server_vm", "one", "production", "high", "internet", "")
	seedAsset(h, "a2", "cmdb", "e2", "server_vm", "two", "production", "high", "internet", "")
	seedAsset(h, "a3", "cmdb", "e3", "server_vm", "three", "production", "high", "internet", "")
	h.users.add("admin", "Admin", domain.RoleAdministrator)

	first, err := h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("admin"), Limit: 2})
	if err != nil {
		t.Fatalf("ListAssets(page1): %v", err)
	}
	if len(first.Assets) != 2 || first.NextCursor == "" {
		t.Fatalf("page1 = %d assets, cursor %q", len(first.Assets), first.NextCursor)
	}
	second, err := h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("admin"), Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("ListAssets(page2): %v", err)
	}
	if len(second.Assets) != 1 || second.NextCursor != "" {
		t.Fatalf("page2 = %d assets, cursor %q, want 1 / empty", len(second.Assets), second.NextCursor)
	}
	if second.Assets[0].ID != "a3" {
		t.Fatalf("page2 first = %q, want a3", second.Assets[0].ID)
	}
}

func TestListAssetsDeniesRolelessUser(t *testing.T) {
	h := newHarness(t)
	seedAsset(h, "a1", "cmdb", "e1", "server_vm", "one", "production", "high", "internet", "")
	h.users.add("nobody", "Nobody") // no roles ⇒ deny-by-default

	_, err := h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("nobody")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("role-less ListAssets = %v (%s), want forbidden", err, kind)
	}
	if len(h.runner.txs) != 0 {
		t.Fatalf("denied read opened %d transactions, want 0", len(h.runner.txs))
	}
}

func TestListAssetsValidatesFilters(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	bad := domain.AssetType("nonsense")
	if _, err := h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("admin"), Type: &bad}); err == nil {
		t.Fatal("invalid type filter must be rejected")
	}
	if _, err := h.svc.ListAssets(context.Background(), application.ListAssetsInput{Actor: userActor("admin"), Limit: 1000}); err == nil {
		t.Fatal("out-of-range limit must be rejected")
	}
}

func TestGetAssetComponentsObjectScope(t *testing.T) {
	h := newHarness(t)
	seedAssetWithComponents(h, "a1", "cmdb", "e1", "u-sys", "comp-2", "comp-1")
	h.users.add("u-sys", "Sys", domain.RoleSystemResponsible)
	h.users.add("u-other", "Other", domain.RoleSystemResponsible)

	res, err := h.svc.GetAssetComponents(context.Background(), application.GetAssetComponentsInput{AssetID: "a1", Actor: userActor("u-sys")})
	if err != nil {
		t.Fatalf("GetAssetComponents(owner): %v", err)
	}
	if res.Asset.ID != "a1" || len(res.Components) != 2 {
		t.Fatalf("asset=%q components=%d", res.Asset.ID, len(res.Components))
	}
	// The components are ordered by natural key, not insertion order.
	if res.Components[0].NaturalKey != "comp-1" {
		t.Fatalf("components not ordered by natural key: %v", res.Components)
	}

	// A different owner is denied on the object scope.
	_, err = h.svc.GetAssetComponents(context.Background(), application.GetAssetComponentsInput{AssetID: "a1", Actor: userActor("u-other")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("non-owner read = %v (%s), want forbidden", err, kind)
	}
}

func TestGetAssetComponentsNotFound(t *testing.T) {
	h := newHarness(t)
	h.users.add("admin", "Admin", domain.RoleAdministrator)
	_, err := h.svc.GetAssetComponents(context.Background(), application.GetAssetComponentsInput{AssetID: "missing", Actor: userActor("admin")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindNotFound {
		t.Fatalf("missing asset = %v (%s), want not-found", err, kind)
	}
}

func TestGetAssetComponentsDeniesRolelessUser(t *testing.T) {
	h := newHarness(t)
	seedAssetWithComponents(h, "a1", "cmdb", "e1", "u-sys", "comp-1")
	h.users.add("nobody", "Nobody")

	_, err := h.svc.GetAssetComponents(context.Background(), application.GetAssetComponentsInput{AssetID: "a1", Actor: userActor("nobody")})
	if kind, _ := application.ErrorKindOf(err); kind != application.KindForbidden {
		t.Fatalf("role-less read = %v (%s), want forbidden", err, kind)
	}
}

// seedAssetWithComponents appends an owned asset with the given component
// natural keys (raw identifiers defaulted) for the components read tests.
func seedAssetWithComponents(h *harness, id, source, external, owner string, naturalKeys ...string) {
	comps := make([]fakeStoredComponent, 0, len(naturalKeys))
	for _, nk := range naturalKeys {
		comps = append(comps, fakeStoredComponent{
			ids:        domain.ComponentIdentifiers{Vendor: "acme", Product: "widget", Version: "1.0.0"},
			naturalKey: nk,
		})
	}
	h.db.assets = append(h.db.assets, fakeStoredAsset{
		id: id, source: source, externalID: external,
		typ: "server_vm", name: id, environment: "production",
		criticality: "high", exposure: "internet", owner: owner,
		updatedAt: fixedNow, components: comps,
	})
}
