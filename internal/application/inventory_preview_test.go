package application

// Table tests of the WP-3.05 inventory preview use case (DEV-059,
// ARCH-003 §1.3 step 2): the read-only diff against the persisted state —
// created / updated / unchanged per asset and component — the row/error
// counts and the data-quality warnings. The current state is faked behind
// the InventoryRepo port; no test touches a database and nothing here can
// write (the port is read-only by construction).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xpera/risksignal/internal/application/normalise"
	"github.com/xpera/risksignal/internal/domain"
)

// fakeInventoryRepo is a scriptable InventoryRepo for preview tests: it
// resolves assets from a map keyed by source+"\x00"+externalID. err, when
// set, fails every lookup (infrastructure failures must propagate).
type fakeInventoryRepo struct {
	assets map[string]CurrentInventoryAsset
	err    error
}

func (f *fakeInventoryRepo) CurrentAsset(_ context.Context, source, externalID string) (CurrentInventoryAsset, bool, error) {
	if f.err != nil {
		return CurrentInventoryAsset{}, false, f.err
	}
	a, ok := f.assets[keyOf(source, externalID)]
	return a, ok, nil
}

// assetRow renders one data row of the canonical shape used below: asset
// (source, external, name) + component (vendor, product, version).
func assetRow(source, external, name, vendor, product, version string) string {
	return inventoryRow(source, external, "server_vm", name, "production", "high", "internet", "", vendor, product, version, "", "", "", "")
}

// currentComponentKey derives the natural key of a persisted component
// the same way the import write path derives it (naturalkey.go priority,
// normalised comparison keys) — the fake state must carry the same keys
// the parsed rows carry or every lookup would miss.
func currentComponentKey(ids domain.ComponentIdentifiers) string {
	key, err := domain.ComponentNaturalKey(ids, normalise.NormaliseKey(ids.Vendor), normalise.NormaliseKey(ids.Product), "")
	if err != nil {
		panic("currentComponentKey: " + err.Error())
	}
	return key
}

// currentAssetOf builds the persisted mirror of assetRow.
func currentAssetOf(source, external, name, vendor, product, version string) CurrentInventoryAsset {
	ids := domain.ComponentIdentifiers{Vendor: vendor, Product: product, Version: version}
	return CurrentInventoryAsset{
		Source: source, ExternalID: external,
		Type: string(domain.AssetTypeServerVM), Name: name,
		Environment: string(domain.EnvironmentProduction),
		Criticality: string(domain.CriticalityHigh), Exposure: string(domain.ExposureInternet),
		Owner: "",
		Components: []CurrentInventoryComponent{
			{IDs: ids, NaturalKey: currentComponentKey(ids)},
		},
	}
}

func TestPreviewInventoryCSVAllCreated(t *testing.T) {
	csv := inventoryCSV(
		assetRow("cmdb", "a1", "n1", "acme", "portal", "1.0.0"),
		assetRow("cmdb", "a2", "n2", "acme", "portal", "2.0.0"),
	)
	res, err := PreviewInventoryCSV(context.Background(), strings.NewReader(csv), &fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 2 || res.ErrorCount != 0 {
		t.Errorf("rows=%d errors=%d", res.Rows, res.ErrorCount)
	}
	if res.AssetsCreated != 2 || res.AssetsUpdated != 0 || res.AssetsUnchanged != 0 {
		t.Errorf("assets created=%d updated=%d unchanged=%d", res.AssetsCreated, res.AssetsUpdated, res.AssetsUnchanged)
	}
	if res.ComponentsCreated != 2 || res.ComponentsUpdated != 0 || res.ComponentsUnchanged != 0 {
		t.Errorf("components created=%d updated=%d unchanged=%d", res.ComponentsCreated, res.ComponentsUpdated, res.ComponentsUnchanged)
	}
	for i, d := range res.AssetDiffs {
		if d.Status != AssetCreated || len(d.Components) != 1 || d.Components[0].Status != AssetCreated {
			t.Errorf("asset diff %d: status=%s components=%+v", i, d.Status, d.Components)
		}
	}
}

func TestPreviewInventoryCSVDiff(t *testing.T) {
	t.Run("identical re-import is fully unchanged", func(t *testing.T) {
		cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
		res, err := PreviewInventoryCSV(context.Background(),
			strings.NewReader(inventoryCSV(assetRow("cmdb", "a1", "n1", "acme", "portal", "1.0.0"))),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.AssetsCreated != 0 || res.AssetsUpdated != 0 || res.AssetsUnchanged != 1 {
			t.Errorf("assets created=%d updated=%d unchanged=%d", res.AssetsCreated, res.AssetsUpdated, res.AssetsUnchanged)
		}
		if res.ComponentsCreated != 0 || res.ComponentsUpdated != 0 || res.ComponentsUnchanged != 1 {
			t.Errorf("components created=%d updated=%d unchanged=%d", res.ComponentsCreated, res.ComponentsUpdated, res.ComponentsUnchanged)
		}
		d := res.AssetDiffs[0]
		if d.Status != AssetUnchanged || d.Components[0].Status != AssetUnchanged {
			t.Errorf("diff: asset=%s component=%s", d.Status, d.Components[0].Status)
		}
	})

	t.Run("asset renamed updates the asset and leaves the component unchanged", func(t *testing.T) {
		cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
		res, err := PreviewInventoryCSV(context.Background(),
			strings.NewReader(inventoryCSV(assetRow("cmdb", "a1", "renamed", "acme", "portal", "1.0.0"))),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.AssetsUpdated != 1 || res.ComponentsUnchanged != 1 {
			t.Errorf("assets updated=%d components unchanged=%d", res.AssetsUpdated, res.ComponentsUnchanged)
		}
	})

	t.Run("component version bump creates a new row under additive upsert", func(t *testing.T) {
		// The vendor/product natural key includes the version, so a
		// version bump is a NEW component row (created), never an update
		// of the old one — additive upsert keeps the old row (absence is
		// not a diff, ARCH-003 §1.3).
		cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
		res, err := PreviewInventoryCSV(context.Background(),
			strings.NewReader(inventoryCSV(assetRow("cmdb", "a1", "n1", "acme", "portal", "2.0.0"))),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.AssetsUnchanged != 1 || res.ComponentsCreated != 1 || res.ComponentsUnchanged != 0 {
			t.Errorf("assets unchanged=%d components created=%d unchanged=%d",
				res.AssetsUnchanged, res.ComponentsCreated, res.ComponentsUnchanged)
		}
	})

	t.Run("case-only change of a vendor/product row updates the component", func(t *testing.T) {
		// The natural key folds the comparison keys (NFKC + lowercase),
		// so "Acme"/"acme" share a key; the raw originals differ, which
		// is exactly the update case of a component whose identity is
		// unchanged.
		cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
		res, err := PreviewInventoryCSV(context.Background(),
			strings.NewReader(inventoryCSV(assetRow("cmdb", "a1", "n1", "Acme", "Portal", "1.0.0"))),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.AssetsUnchanged != 1 || res.ComponentsUpdated != 1 || res.ComponentsCreated != 0 {
			t.Errorf("assets unchanged=%d components updated=%d created=%d",
				res.AssetsUnchanged, res.ComponentsUpdated, res.ComponentsCreated)
		}
	})

	t.Run("new component on an existing asset", func(t *testing.T) {
		cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
		csv := inventoryCSV(
			assetRow("cmdb", "a1", "n1", "acme", "portal", "1.0.0"),
			assetRow("cmdb", "a1", "n1", "acme", "gateway", "1.0.0"),
		)
		res, err := PreviewInventoryCSV(context.Background(), strings.NewReader(csv),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.AssetsUnchanged != 1 || res.ComponentsUnchanged != 1 || res.ComponentsCreated != 1 {
			t.Errorf("assets unchanged=%d components unchanged=%d created=%d",
				res.AssetsUnchanged, res.ComponentsUnchanged, res.ComponentsCreated)
		}
	})

	t.Run("component version bump updates the component", func(t *testing.T) {
		// A version-bearing identity (here: the image digest) keeps the
		// natural key stable across a version/tag change; the raw image
		// reference differs — the update case.
		digest := digest64()
		ids := domain.ComponentIdentifiers{Digest: digest, Image: "registry/x/img:v1"}
		cur := CurrentInventoryAsset{
			Source: "cmdb", ExternalID: "a1",
			Type: string(domain.AssetTypeContainerImage), Name: "n1",
			Environment: string(domain.EnvironmentProduction),
			Criticality: string(domain.CriticalityHigh), Exposure: string(domain.ExposureInternet),
			Owner: "",
			Components: []CurrentInventoryComponent{
				{IDs: ids, NaturalKey: currentComponentKey(ids)},
			},
		}
		row := inventoryRow("cmdb", "a1", "container_image", "n1", "production", "high", "internet", "", "", "", "", "", "", "registry/x/img:v2", digest)
		res, err := PreviewInventoryCSV(context.Background(), strings.NewReader(inventoryCSV(row)),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.AssetsUnchanged != 1 || res.ComponentsUpdated != 1 || res.ComponentsCreated != 0 {
			t.Errorf("assets unchanged=%d components updated=%d created=%d",
				res.AssetsUnchanged, res.ComponentsUpdated, res.ComponentsCreated)
		}
	})

	t.Run("persisted components the file does not carry stay untouched", func(t *testing.T) {
		// Additive upsert: absence of a row never deactivates or diffs
		// it (ARCH-003 §1.3). The persisted second component appears in
		// no diff and in no tally.
		cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
		cur.Components = append(cur.Components, CurrentInventoryComponent{
			IDs:        domain.ComponentIdentifiers{Vendor: "acme", Product: "legacy", Version: "0.9.0"},
			NaturalKey: currentComponentKey(domain.ComponentIdentifiers{Vendor: "acme", Product: "legacy", Version: "0.9.0"}),
		})
		res, err := PreviewInventoryCSV(context.Background(),
			strings.NewReader(inventoryCSV(assetRow("cmdb", "a1", "n1", "acme", "portal", "1.0.0"))),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.ComponentsUnchanged != 1 || res.ComponentsCreated != 0 {
			t.Errorf("components unchanged=%d created=%d", res.ComponentsUnchanged, res.ComponentsCreated)
		}
	})

	t.Run("identifier gained on an existing component creates a distinct row", func(t *testing.T) {
		// The natural key changes when a stronger identifier appears:
		// the old vendor/product row stays (absence is not a diff) and
		// the new cpe row is created.
		cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
		row := inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "high", "internet", "", "acme", "portal", "1.0.0", cpe23(), "", "", "")
		res, err := PreviewInventoryCSV(context.Background(), strings.NewReader(inventoryCSV(row)),
			&fakeInventoryRepo{assets: map[string]CurrentInventoryAsset{keyOf("cmdb", "a1"): cur}})
		if err != nil {
			t.Fatal(err)
		}
		if res.ComponentsCreated != 1 {
			t.Errorf("components created=%d, want 1 (new cpe natural key)", res.ComponentsCreated)
		}
	})
}

func TestPreviewInventoryCSVWarningsAndErrors(t *testing.T) {
	t.Run("unknown criticality and exposure surface as warnings", func(t *testing.T) {
		csv := inventoryCSV(inventoryRow("cmdb", "a1", "server_vm", "n1", "production", "unknown", "unknown", "", "acme", "p1", "1.0.0", "", "", "", ""))
		res, err := PreviewInventoryCSV(context.Background(), strings.NewReader(csv), &fakeInventoryRepo{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Warnings) != 2 {
			t.Fatalf("warnings=%d, want 2", len(res.Warnings))
		}
		if w := res.Warnings[0]; w.Field != "criticality" || w.Line != 2 {
			t.Errorf("warning 0: %+v", res.Warnings[0])
		}
		if w := res.Warnings[1]; w.Field != "exposure" || w.Line != 2 {
			t.Errorf("warning 1: %+v", res.Warnings[1])
		}
		if res.ErrorCount != 0 || res.AssetsCreated != 1 {
			t.Errorf("errors=%d assets created=%d", res.ErrorCount, res.AssetsCreated)
		}
	})

	t.Run("error rows are counted but excluded from the diff", func(t *testing.T) {
		csv := inventoryCSV(
			assetRow("cmdb", "a1", "n1", "acme", "portal", "1.0.0"),
			inventoryRow("cmdb", "a2", "car", "n2", "production", "high", "internet", "", "acme", "p1", "1.0.0", "", "", "", ""), // bad type
		)
		res, err := PreviewInventoryCSV(context.Background(), strings.NewReader(csv), &fakeInventoryRepo{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Rows != 2 || res.ErrorCount != 1 || len(res.Errors) != 1 {
			t.Fatalf("rows=%d errors=%d", res.Rows, res.ErrorCount)
		}
		if res.Errors[0].Line != 3 || res.Errors[0].Column != "type" {
			t.Errorf("error position: %s", res.Errors[0])
		}
		if res.AssetsCreated != 1 || res.ComponentsCreated != 1 {
			t.Errorf("assets created=%d components created=%d (bad row must not diff)", res.AssetsCreated, res.ComponentsCreated)
		}
	})

	t.Run("current-state read failures propagate", func(t *testing.T) {
		repoErr := errors.New("db down")
		_, err := PreviewInventoryCSV(context.Background(),
			strings.NewReader(inventoryCSV(assetRow("cmdb", "a1", "n1", "acme", "portal", "1.0.0"))),
			&fakeInventoryRepo{err: repoErr})
		if err == nil {
			t.Fatal("expected the read failure to propagate")
		}
		var appErr *Error
		if !errors.As(err, &appErr) || appErr.Kind != KindInfra {
			t.Errorf("err=%v, want an infrastructure-class application error", err)
		}
	})

	t.Run("nil current-state reader", func(t *testing.T) {
		_, err := PreviewInventoryCSV(context.Background(), strings.NewReader("x"), nil)
		if err == nil {
			t.Fatal("nil current-state reader must error")
		}
	})
}

func TestPreviewInventoryCSVMixedState(t *testing.T) {
	// One asset already current (unchanged, one identical component), one
	// asset needing an update, one brand new — the tallies must split.
	cur := currentAssetOf("cmdb", "a1", "n1", "acme", "portal", "1.0.0")
	curB := currentAssetOf("cmdb", "b1", "nb", "acme", "portal", "1.0.0")
	csv := inventoryCSV(
		assetRow("cmdb", "a1", "n1", "acme", "portal", "1.0.0"),        // unchanged
		assetRow("cmdb", "b1", "renamed-b", "acme", "portal", "1.0.0"), // asset updated, component unchanged
		assetRow("cmdb", "c1", "nc", "acme", "portal", "3.0.0"),        // created
	)
	res, err := PreviewInventoryCSV(context.Background(), strings.NewReader(csv), &fakeInventoryRepo{
		assets: map[string]CurrentInventoryAsset{
			keyOf("cmdb", "a1"): cur,
			keyOf("cmdb", "b1"): curB,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 3 || res.ErrorCount != 0 {
		t.Errorf("rows=%d errors=%d", res.Rows, res.ErrorCount)
	}
	if res.AssetsCreated != 1 || res.AssetsUpdated != 1 || res.AssetsUnchanged != 1 {
		t.Errorf("assets created=%d updated=%d unchanged=%d", res.AssetsCreated, res.AssetsUpdated, res.AssetsUnchanged)
	}
	if res.ComponentsCreated != 1 || res.ComponentsUpdated != 0 || res.ComponentsUnchanged != 2 {
		t.Errorf("components created=%d updated=%d unchanged=%d", res.ComponentsCreated, res.ComponentsUpdated, res.ComponentsUnchanged)
	}
	if len(res.AssetDiffs) != 3 {
		t.Fatalf("asset diffs=%d, want 3", len(res.AssetDiffs))
	}
	if res.AssetDiffs[0].Status != AssetUnchanged || res.AssetDiffs[1].Status != AssetUpdated || res.AssetDiffs[2].Status != AssetCreated {
		t.Errorf("diff order/status: %s / %s / %s", res.AssetDiffs[0].Status, res.AssetDiffs[1].Status, res.AssetDiffs[2].Status)
	}
}
