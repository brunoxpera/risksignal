package application

// This file implements the I5b asset read use cases of ARCH-006 §2.2
// (WP-5b.03): ListAssets (the cursor-paginated, filterable asset working
// list, GET /assets) and GetAssetComponents (one asset with its components,
// GET /assets/{id}/components). Both are pure reads over the I3
// assets/components tables through the AssetRepo read port (DEV-098) — no
// domain change, no write — and both are permission-gated on inventory.read
// with the deny-by-default object-scope rule of ARCH-005 §5: a
// Systemverantwortliche (the only role holding inventory.read at the
// `assigned` scope) reads only the assets it owns (owner_id =
// principal.id). The gate runs before any read; a denied read returns a
// ForbiddenError (403) and opens no transaction.
//
// The use cases mirror ListSignals/GetSignal: the object-scope membership
// check happens before the load, the per-object check on the loaded asset's
// owner after it (GetAssetComponents), and the query path injects the
// owner filter for the scoped list (ListAssets).

import (
	"context"
	"errors"

	"github.com/brunoxpera/risksignal/internal/domain"
)

// errAssetsNotWired is the programming error of the asset read use cases
// invoked without the AssetRepo read port.
var errAssetsNotWired = errors.New("application: asset read repository is not wired")

// ListAssetsInput is the asset working-list query (ARCH-006 §2.2, GET
// /assets): optional type/environment/criticality/exposure/owner/source
// filters, an opaque cursor and a page size. Limit 0 means the default (20);
// limits above maxListLimit are rejected. Actor is the authenticated
// principal: inventory.read is gated per the matrix and an `assigned`/`own`
// grant restricts the read to the assets the principal owns (owner_id =
// principal.id — the OwnerID filter is overwritten, a scoped principal can
// never widen its read).
type ListAssetsInput struct {
	Limit       int
	Cursor      string
	Type        *domain.AssetType
	Environment *domain.Environment
	Criticality *domain.Criticality
	Exposure    *domain.Exposure
	OwnerID     *string
	Source      *string
	Actor       Actor
}

// ListAssetsResult is one page of the asset working list. NextCursor is empty
// on the last page.
type ListAssetsResult struct {
	Assets     []Asset
	NextCursor string
}

// ListAssets returns one cursor-paginated page of the asset working list,
// ordered by created_at then id (a stable sort — the AssetRepo.ListAssets
// contract). The repository contract returns at most limit+1 rows so the page
// boundary is exact: limit+1 assets mean a further page exists. inventory.read
// gates the read per the matrix; an `assigned`/`own` grant scopes it to the
// principal's owned assets (ARCH-005 §5).
func (s *Service) ListAssets(ctx context.Context, in ListAssetsInput) (ListAssetsResult, error) {
	const op = "list_assets"

	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return ListAssetsResult{}, err
	}
	// inventory.read per the matrix: a role-less user (or one without
	// inventory.read) is denied; an `assigned`/`own` grant scopes the query to
	// the principal's owned assets (owner_id = principal.id) — the query path
	// half of the object-scope rule (ARCH-005 §5).
	scope := principal.GrantedScope(domain.PermissionInventoryRead)
	if principal.InternalID != "" && scope == domain.ScopeNone {
		return ListAssetsResult{}, Forbiddenf(op, "principal %q is not permitted %s", principal.InternalID, domain.PermissionInventoryRead)
	}

	limit := in.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	if limit < 0 || limit > maxListLimit {
		return ListAssetsResult{}, Validationf(op, "limit %d outside [1,%d] (0 means the default %d)", in.Limit, maxListLimit, defaultListLimit)
	}
	if in.Type != nil && !in.Type.Valid() {
		return ListAssetsResult{}, Validationf(op, "invalid type filter %q", *in.Type)
	}
	if in.Environment != nil && !in.Environment.Valid() {
		return ListAssetsResult{}, Validationf(op, "invalid environment filter %q", *in.Environment)
	}
	if in.Criticality != nil && !in.Criticality.Valid() {
		return ListAssetsResult{}, Validationf(op, "invalid criticality filter %q", *in.Criticality)
	}
	if in.Exposure != nil && !in.Exposure.Valid() {
		return ListAssetsResult{}, Validationf(op, "invalid exposure filter %q", *in.Exposure)
	}
	offset, err := decodeCursor(op, in.Cursor)
	if err != nil {
		return ListAssetsResult{}, err
	}
	if s.assets == nil {
		return ListAssetsResult{}, InfraError(op, errAssetsNotWired)
	}

	filter := AssetFilter{
		Type:        in.Type,
		Environment: in.Environment,
		Criticality: in.Criticality,
		Exposure:    in.Exposure,
		Source:      in.Source,
	}
	// The object scope wins over any supplied owner filter: a scoped grant
	// sees only its own assets (ARCH-005 §5).
	switch {
	case principal.InternalID != "" && (scope == domain.ScopeAssigned || scope == domain.ScopeOwn):
		owner := principal.InternalID
		filter.OwnerID = &owner
	default:
		filter.OwnerID = in.OwnerID
	}

	rows, err := s.assets.ListAssets(ctx, filter, limit, offset)
	if err != nil {
		return ListAssetsResult{}, err
	}

	res := ListAssetsResult{}
	if len(rows) > limit {
		res.Assets = rows[:limit]
		res.NextCursor = encodeCursor(offset + limit)
	} else {
		res.Assets = rows
	}
	return res, nil
}

// GetAssetComponentsInput is the one-asset detail read (ARCH-006 §2.2, GET
// /assets/{id}/components): the asset id and the authenticated principal.
type GetAssetComponentsInput struct {
	AssetID string
	Actor   Actor
}

// GetAssetComponents returns one asset together with its ordered components
// (ARCH-006 §2.2). An unknown id is a not-found error (the HTTP layer maps it
// to a 404). A user principal without inventory.read, or with an
// `assigned`/`own` grant on an asset it does not own, is denied with a
// ForbiddenError (403) before the view is returned (ARCH-005 §5).
func (s *Service) GetAssetComponents(ctx context.Context, in GetAssetComponentsInput) (AssetComponents, error) {
	const op = "get_asset_components"

	if in.AssetID == "" {
		return AssetComponents{}, Validationf(op, "asset id must not be empty")
	}
	principal, err := s.principalFor(ctx, op, in.Actor)
	if err != nil {
		return AssetComponents{}, err
	}
	// Membership first (a role-less user is denied before the load), then the
	// object-scope check on the loaded asset's owner.
	scope := principal.GrantedScope(domain.PermissionInventoryRead)
	if principal.InternalID != "" && scope == domain.ScopeNone {
		return AssetComponents{}, Forbiddenf(op, "principal %q is not permitted %s", principal.InternalID, domain.PermissionInventoryRead)
	}
	if s.assets == nil {
		return AssetComponents{}, InfraError(op, errAssetsNotWired)
	}
	res, err := s.assets.GetAssetComponents(ctx, in.AssetID)
	if err != nil {
		return AssetComponents{}, err
	}
	if err := s.authorizeObject(op, principal, domain.PermissionInventoryRead, scope, res.Asset.Owner); err != nil {
		return AssetComponents{}, err
	}
	return res, nil
}
