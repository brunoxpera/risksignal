package application_test

// Fakes for the I5b application use cases (WP-5b.03 / DEV-099): the asset read
// repo (AssetRepo), the staged-import store (InventoryImportRepo) and the
// user/role administration methods on the shared fake user store
// (UserAdminRepo). They are in-memory over the fakeDB and stage their writes on
// the fake transaction so commit/rollback semantics hold.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// ---------------------------------------------------------------------------
// fakeAssetRepo (application.AssetRepo)

type fakeAssetRepo struct{ db *fakeDB }

var _ application.AssetRepo = (*fakeAssetRepo)(nil)

// ListAssets mirrors the postgres adapter: it filters the committed assets and
// returns the offset+limit+1 window (so the caller can detect a further page).
func (f *fakeAssetRepo) ListAssets(_ context.Context, filter application.AssetFilter, limit, offset int) ([]application.Asset, error) {
	all := make([]application.Asset, 0, len(f.db.assets))
	for _, a := range f.db.assets {
		if filter.Type != nil && string(*filter.Type) != a.typ {
			continue
		}
		if filter.Environment != nil && string(*filter.Environment) != a.environment {
			continue
		}
		if filter.Criticality != nil && string(*filter.Criticality) != a.criticality {
			continue
		}
		if filter.Exposure != nil && string(*filter.Exposure) != a.exposure {
			continue
		}
		if filter.OwnerID != nil && *filter.OwnerID != a.owner {
			continue
		}
		if filter.Source != nil && *filter.Source != a.source {
			continue
		}
		all = append(all, assetReadView(a))
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.Before(all[j].CreatedAt)
		}
		return all[i].ID < all[j].ID
	})
	if offset >= len(all) {
		return []application.Asset{}, nil
	}
	all = all[offset:]
	if len(all) > limit+1 {
		all = all[:limit+1]
	}
	return all, nil
}

// GetAssetComponents returns one asset with its components ordered by natural
// key; a missing id is a not-found error.
func (f *fakeAssetRepo) GetAssetComponents(_ context.Context, assetID string) (application.AssetComponents, error) {
	for _, a := range f.db.assets {
		if a.id != assetID {
			continue
		}
		comps := make([]application.Component, 0, len(a.components))
		for _, c := range a.components {
			comps = append(comps, componentReadView(a.id, c))
		}
		sort.SliceStable(comps, func(i, j int) bool { return comps[i].NaturalKey < comps[j].NaturalKey })
		return application.AssetComponents{Asset: assetReadView(a), Components: comps}, nil
	}
	return application.AssetComponents{}, application.NotFoundError("assets.get_components", fmt.Errorf("asset %s not found", assetID))
}

// assetReadView projects one stored fake asset onto the application read model.
func assetReadView(a fakeStoredAsset) application.Asset {
	return application.Asset{
		ID:            a.id,
		ExternalID:    a.externalID,
		Source:        a.source,
		Type:          domain.AssetType(a.typ),
		Name:          a.name,
		Environment:   domain.Environment(a.environment),
		Criticality:   domain.Criticality(a.criticality),
		Exposure:      domain.Exposure(a.exposure),
		Owner:         a.owner,
		CreatedAt:     a.updatedAt,
		UpdatedAt:     a.updatedAt,
		DeactivatedAt: a.deactivatedAt,
	}
}

func componentReadView(assetID string, c fakeStoredComponent) application.Component {
	return application.Component{
		AssetID:       assetID,
		Vendor:        c.ids.Vendor,
		Product:       c.ids.Product,
		Version:       c.ids.Version,
		CPE:           c.ids.CPE,
		PURL:          c.ids.PURL,
		Image:         c.ids.Image,
		Digest:        c.ids.Digest,
		VendorNorm:    c.vendorNorm,
		ProductNorm:   c.productNorm,
		VersionNorm:   c.versionNorm,
		VersionScheme: c.scheme,
		NaturalKey:    c.naturalKey,
	}
}

// ---------------------------------------------------------------------------
// fakeInventoryImportRepo (application.InventoryImportRepo)

type fakeInventoryImportRepo struct{ db *fakeDB }

var _ application.InventoryImportRepo = (*fakeInventoryImportRepo)(nil)

func (f *fakeInventoryImportRepo) Insert(_ context.Context, tx application.Tx, rec application.InventoryImportRecord) (application.InventoryImportRecord, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.InventoryImportRecord{}, err
	}
	ftx.record("import.insert")
	f.db.nextImportID++
	rec.ID = fmt.Sprintf("import-%d", f.db.nextImportID)
	if rec.Status == "" {
		rec.Status = application.InventoryImportPending
	}
	ftx.staged.importInserts = append(ftx.staged.importInserts, rec)
	return rec, nil
}

func (f *fakeInventoryImportRepo) Get(_ context.Context, id string) (application.InventoryImportRecord, error) {
	for _, r := range f.db.imports {
		if r.ID == id {
			return r, nil
		}
	}
	return application.InventoryImportRecord{}, application.NotFoundError("import.get", fmt.Errorf("import %s not found", id))
}

func (f *fakeInventoryImportRepo) MarkCommitted(_ context.Context, tx application.Tx, id string, counts application.InventoryImportCounts, now time.Time) (application.InventoryImportRecord, bool, error) {
	ftx, err := fakeTxOf(tx)
	if err != nil {
		return application.InventoryImportRecord{}, false, err
	}
	ftx.record("import.mark_committed")
	for _, r := range f.db.imports {
		if r.ID != id {
			continue
		}
		if r.Status != application.InventoryImportPending {
			return r, false, nil // guard did not match: no-op (already committed/failed)
		}
		r.Status = application.InventoryImportCommitted
		r.CommittedAt = now
		r.AssetsCreated = counts.AssetsCreated
		r.AssetsUpdated = counts.AssetsUpdated
		r.ComponentsCreated = counts.ComponentsCreated
		r.ComponentsUpdated = counts.ComponentsUpdated
		ftx.staged.importMarks = append(ftx.staged.importMarks, storedImportMark{id: id, counts: counts, now: now})
		return r, true, nil
	}
	return application.InventoryImportRecord{}, false, nil
}

func (f *fakeInventoryImportRepo) List(_ context.Context) ([]application.InventoryImportRecord, error) {
	return append([]application.InventoryImportRecord(nil), f.db.imports...), nil
}

// ---------------------------------------------------------------------------
// fakeUserRepo — the UserAdminRepo half (application.UserAdminRepo)

var _ application.UserAdminRepo = (*fakeUserRepo)(nil)

func (f *fakeUserRepo) GetUser(_ context.Context, id string) (application.UserRecord, error) {
	if _, ok := f.byID[id]; !ok {
		return application.UserRecord{}, application.NotFoundError("user.get", fmt.Errorf("user %s not found", id))
	}
	return f.record(id), nil
}

func (f *fakeUserRepo) ListUsers(_ context.Context) ([]application.UserRecord, error) {
	out := make([]application.UserRecord, 0, len(f.byID))
	for id := range f.byID {
		out = append(out, f.record(id))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].DisplayName != out[j].DisplayName {
			return out[i].DisplayName < out[j].DisplayName
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (f *fakeUserRepo) GrantRole(_ context.Context, tx application.Tx, userID string, role domain.Role, at time.Time, by string) error {
	if _, err := fakeTxOf(tx); err != nil {
		return err
	}
	if _, ok := f.byID[userID]; !ok {
		return application.NotFoundError("user.grant_role", fmt.Errorf("user %s not found", userID))
	}
	for _, r := range f.roles[userID] {
		if r == role {
			return nil // idempotent
		}
	}
	f.roles[userID] = append(f.roles[userID], role)
	return nil
}

func (f *fakeUserRepo) RevokeRole(_ context.Context, tx application.Tx, userID string, role domain.Role) error {
	if _, err := fakeTxOf(tx); err != nil {
		return err
	}
	roles := f.roles[userID]
	out := roles[:0]
	for _, r := range roles {
		if r != role {
			out = append(out, r)
		}
	}
	f.roles[userID] = out
	return nil
}

func (f *fakeUserRepo) DeactivateUser(_ context.Context, tx application.Tx, userID string, now time.Time) error {
	if _, err := fakeTxOf(tx); err != nil {
		return err
	}
	u, ok := f.byID[userID]
	if !ok {
		return application.NotFoundError("user.deactivate", fmt.Errorf("user %s not found", userID))
	}
	if !u.DeactivatedAt.IsZero() {
		return application.ConflictError("user.deactivate", fmt.Errorf("user %s already deactivated", userID))
	}
	u.DeactivatedAt = now
	f.byID[userID] = u
	return nil
}

// record builds the administration read model of one registered user.
func (f *fakeUserRepo) record(id string) application.UserRecord {
	u := f.byID[id]
	return application.UserRecord{
		ID:            u.ID,
		SubjectID:     u.SubjectID,
		DisplayName:   u.DisplayName,
		Roles:         append([]domain.Role(nil), f.roles[id]...),
		DeactivatedAt: u.DeactivatedAt,
		LastLoginAt:   fixedNow,
		CreatedAt:     fixedNow,
	}
}
