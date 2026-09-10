// HTTP handlers of the asset reads (ARCH-006 §2.2, WP-5b.05): the generated
// operations GET /api/v1/assets and GET /api/v1/assets/{id}/components. They
// translate the wire request onto the application.ListAssets /
// GetAssetComponents read use cases (the gate of record, gated on
// inventory.read with the object scope enforced inside the use case) and map
// their outcome onto the typed response objects. The handlers decide no rights:
// the owner-scope injection and the deny-by-default check stay in the use case.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/brunoxpera/risksignal/internal/adapters/httpapi/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// AssetsRead is the application surface of the asset reads the handler
// delegates to (application.Service).
type AssetsRead interface {
	ActorResolver
	ListAssets(ctx context.Context, in application.ListAssetsInput) (application.ListAssetsResult, error)
	GetAssetComponents(ctx context.Context, in application.GetAssetComponentsInput) (application.AssetComponents, error)
}

// assetsHandler implements the two asset-read operations.
type assetsHandler struct {
	assets AssetsRead
	logger *slog.Logger
}

// ListAssets implements GET /api/v1/assets (ARCH-006 §2.2): the filterable,
// cursor-paginated asset working list. The enum filters are validated against
// the generated contract here (the binding converts strings but does not check
// membership); the page-size and cursor semantics stay in the use case. An
// invalid filter is the typed 400 without reaching the use case.
func (h *assetsHandler) ListAssets(ctx context.Context, request gen.ListAssetsRequestObject) (gen.ListAssetsResponseObject, error) {
	if h.assets == nil {
		return gen.ListAssets500JSONResponse(h.internalProblem(ctx, errors.New("asset read handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.assets)
	if err != nil {
		return h.listError(ctx, err)
	}
	in := application.ListAssetsInput{Actor: actor}
	params := request.Params
	if params.Type != nil {
		if !params.Type.Valid() {
			return gen.ListAssets400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid type filter %q", *params.Type))), nil
		}
		t := domain.AssetType(*params.Type)
		in.Type = &t
	}
	if params.Environment != nil {
		if !params.Environment.Valid() {
			return gen.ListAssets400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid environment filter %q", *params.Environment))), nil
		}
		e := domain.Environment(*params.Environment)
		in.Environment = &e
	}
	if params.Criticality != nil {
		if !params.Criticality.Valid() {
			return gen.ListAssets400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid criticality filter %q", *params.Criticality))), nil
		}
		c := domain.Criticality(*params.Criticality)
		in.Criticality = &c
	}
	if params.Exposure != nil {
		if !params.Exposure.Valid() {
			return gen.ListAssets400JSONResponse(problemFromContext(ctx, http.StatusBadRequest, titleInvalidRequest,
				fmt.Sprintf("invalid exposure filter %q", *params.Exposure))), nil
		}
		e := domain.Exposure(*params.Exposure)
		in.Exposure = &e
	}
	in.OwnerID = params.OwnerId
	in.Source = params.Source
	if params.Limit != nil {
		in.Limit = *params.Limit
	}
	if params.Cursor != nil {
		in.Cursor = *params.Cursor
	}

	page, err := h.assets.ListAssets(ctx, in)
	if err != nil {
		return h.listError(ctx, err)
	}
	data := make([]gen.Asset, 0, len(page.Assets))
	for _, a := range page.Assets {
		data = append(data, toGenAsset(a))
	}
	var nextCursor *string
	if page.NextCursor != "" {
		nextCursor = &page.NextCursor
	}
	return gen.ListAssets200JSONResponse(gen.AssetList{Data: data, NextCursor: nextCursor}), nil
}

// GetAssetComponents implements GET /api/v1/assets/{id}/components (ARCH-006
// §2.2): one asset with its ordered components. An unknown id is the typed
// 404; a malformed id fails validation in the repository and is the typed 400.
func (h *assetsHandler) GetAssetComponents(ctx context.Context, request gen.GetAssetComponentsRequestObject) (gen.GetAssetComponentsResponseObject, error) {
	if h.assets == nil {
		return gen.GetAssetComponents500JSONResponse(h.internalProblem(ctx, errors.New("asset read handler is not wired"))), nil
	}
	actor, err := resolveActor(ctx, h.assets)
	if err != nil {
		return h.detailError(ctx, err)
	}
	res, err := h.assets.GetAssetComponents(ctx, application.GetAssetComponentsInput{AssetID: request.Id, Actor: actor})
	if err != nil {
		return h.detailError(ctx, err)
	}
	return gen.GetAssetComponents200JSONResponse(toGenAssetComponents(res)), nil
}

func (h *assetsHandler) listError(ctx context.Context, err error) (gen.ListAssetsResponseObject, error) {
	status, title, detail := actorProblem(err)
	switch status {
	case http.StatusBadRequest:
		return gen.ListAssets400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusForbidden:
		return gen.ListAssets403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	default:
		return gen.ListAssets500JSONResponse(h.internalProblem(ctx, err)), nil
	}
}

func (h *assetsHandler) detailError(ctx context.Context, err error) (gen.GetAssetComponentsResponseObject, error) {
	status, title, detail := actorProblem(err)
	switch status {
	case http.StatusBadRequest:
		return gen.GetAssetComponents400JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusForbidden:
		return gen.GetAssetComponents403JSONResponse(problemFromContext(ctx, status, title, detail)), nil
	case http.StatusNotFound:
		return gen.GetAssetComponents404JSONResponse(problemFromContext(ctx, http.StatusNotFound, titleAssetNotFound, detail)), nil
	default:
		return gen.GetAssetComponents500JSONResponse(h.internalProblem(ctx, err)), nil
	}
}

// internalProblem logs err with its correlation id and returns the generic
// internal-error problem detail (no detail field).
func (h *assetsHandler) internalProblem(ctx context.Context, err error) gen.ProblemDetails {
	h.logger.ErrorContext(ctx, "asset read request failed", slog.Any("error", err))
	return problemFromContext(ctx, http.StatusInternalServerError, titleInternalError, "")
}

// toGenAsset maps the application asset read model onto the generated Asset —
// the wire contract, never hand-rolled. A zero DeactivatedAt/VerifiedAt is the
// false flag; an unassigned owner is the wire null.
func toGenAsset(a application.Asset) gen.Asset {
	var owner *string
	if a.Owner != "" {
		o := a.Owner
		owner = &o
	}
	return gen.Asset{
		Id:          a.ID,
		ExternalId:  a.ExternalID,
		Source:      a.Source,
		Type:        gen.AssetType(a.Type),
		Name:        a.Name,
		Environment: gen.Environment(a.Environment),
		Criticality: gen.Criticality(a.Criticality),
		Exposure:    gen.Exposure(a.Exposure),
		Owner:       owner,
		Deactivated: !a.DeactivatedAt.IsZero(),
		Verified:    !a.VerifiedAt.IsZero(),
	}
}

// toGenAssetComponents maps one asset with its components onto the generated
// AssetComponents.
func toGenAssetComponents(res application.AssetComponents) gen.AssetComponents {
	components := make([]gen.Component, 0, len(res.Components))
	for _, c := range res.Components {
		components = append(components, gen.Component{
			Id:            c.ID,
			AssetId:       c.AssetID,
			Vendor:        c.Vendor,
			Product:       c.Product,
			Version:       c.Version,
			Cpe:           c.CPE,
			Purl:          c.PURL,
			Image:         c.Image,
			Digest:        c.Digest,
			VersionScheme: gen.VersionScheme(c.VersionScheme),
			Deactivated:   false,
		})
	}
	return gen.AssetComponents{Asset: toGenAsset(res.Asset), Components: components}
}
