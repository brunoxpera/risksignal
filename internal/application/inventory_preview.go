package application

// This file implements the preview use case of the WP-3.05 inventory
// import (ARCH-003 §1.3 step 2, DEV-059): a read-only diff of one parsed
// inventory CSV against the persisted state. For every asset the file
// would import (grouped by (source, external_id)) and every component of
// it, the preview classifies the effect of a commit as created, updated
// or unchanged, reports the row/error counts and the data-quality
// warnings (unknown criticality/exposure). Preview never writes: the only
// persistence contact is the read-only InventoryRepo port, which the CLI
// composition root (DEV-060) wires to the postgres adapter over the
// DEV-056 read queries (ListComponentsByAsset); nothing in this file can
// mutate state.
//
// Classification semantics (additive-upsert import, ARCH-003 §1.3):
//
//   - an asset is created when no row with its (source, external_id)
//     exists, updated when it exists with different asset fields
//     (type/name/environment/criticality/exposure/owner — the columns
//     the commit upsert refreshes), unchanged otherwise;
//   - a component is created when no component of its asset carries its
//     natural key, updated when one exists with different raw
//     identifiers (vendor/product/version/cpe/purl/image/digest — the
//     columns the natural-key upsert refreshes), unchanged otherwise.
//     The derived keys (vendor_norm/product_norm/version_scheme) are
//     deterministic functions of the raw identifiers and are therefore
//     not diffed separately. Note that the natural key of the
//     vendor/product fallback includes the version (naturalkey.go), so a
//     version change of such a row is a NEW row (created) under the
//     additive upsert, never an update of the old one;
//   - absence is never a diff: rows of the current state that the file
//     does not carry stay untouched (additive upsert — deactivation is
//     an explicit lifecycle action, never an import side effect).
//
// Rows that failed validation are reported positioned (like validate)
// and contribute to no diff — preview shows exactly what a commit of the
// file's clean rows would change, next to the errors that would block
// those rows.

import (
	"context"
	"fmt"
	"io"

	"github.com/xpera/risksignal/internal/domain"
)

// AssetDiffStatus classifies one parsed asset or component against the
// current state (ARCH-003 §1.3 preview: created / updated / unchanged).
type AssetDiffStatus string

// The three diff outcomes of the preview classification.
const (
	AssetCreated   AssetDiffStatus = "created"
	AssetUpdated   AssetDiffStatus = "updated"
	AssetUnchanged AssetDiffStatus = "unchanged"
)

// CurrentInventoryComponent is one persisted component of the current
// state, as the preview diffs against it: the raw identifiers (verbatim,
// NULL as "") and the natural key — the identity a commit upsert would
// conflict on (UQ (asset_id, natural_key)).
type CurrentInventoryComponent struct {
	IDs        domain.ComponentIdentifiers
	NaturalKey string
}

// CurrentInventoryAsset is the persisted state of one asset, as the
// preview diffs against it: the row's (source, external_id) identity, its
// fields as plain strings (verbatim, NULL as "") and its components.
type CurrentInventoryAsset struct {
	Source      string
	ExternalID  string
	Type        string
	Name        string
	Environment string
	Criticality string
	Exposure    string
	Owner       string

	Components []CurrentInventoryComponent
}

// InventoryRepo is the read-only current-state port of the preview
// (ARCH-003 §1.3 step 2): it resolves one asset by its import key
// (source, external_id) together with its components, or reports that no
// such asset exists (found=false — the normal "created" outcome, not an
// error). The postgres implementation over the DEV-056 read queries
// (ListComponentsByAsset and the asset lookup by UQ (source,
// external_id)) lands with the CLI composition root (DEV-060); preview
// itself programs against this read only and never writes through it.
type InventoryRepo interface {
	CurrentAsset(ctx context.Context, source, externalID string) (CurrentInventoryAsset, bool, error)
}

// ComponentDiff is the per-component preview classification of one parsed
// component.
type ComponentDiff struct {
	Line   int
	Status AssetDiffStatus
	IDs    domain.ComponentIdentifiers
}

// AssetDiff is the per-asset preview classification of one parsed asset
// group: the asset status plus the classification of every component it
// carries. Lines are the contributing data lines of the group.
type AssetDiff struct {
	Source     string
	ExternalID string
	Status     AssetDiffStatus
	Lines      []int
	Asset      InventoryAsset
	Components []ComponentDiff
}

// PreviewResult is the full preview report (ARCH-003 §1.3 step 2): the
// row/error counts, the data-quality warnings and the created/updated/
// unchanged tallies over the parsed assets and components, with the
// per-asset breakdown in AssetDiffs. AssetsCreated etc. count the parsed
// groups of the file (a group whose rows all failed validation appears in
// no diff and in no tally).
type PreviewResult struct {
	Rows       int
	ErrorCount int
	Errors     []InventoryProblem
	Warnings   []InventoryWarning

	AssetsCreated   int
	AssetsUpdated   int
	AssetsUnchanged int

	ComponentsCreated   int
	ComponentsUpdated   int
	ComponentsUnchanged int

	AssetDiffs []AssetDiff
}

// PreviewInventoryCSV parses one inventory CSV and diffs the clean rows
// against the persisted state read through current (ARCH-003 §1.3 step
// 2). Read-only: current is only read from. Every content failure is
// positioned in PreviewResult.Errors; a failing row never aborts the
// diff of the rest of the file. The returned error is non-nil for
// impossible parses (input too large, unreadable input) and for current-
// state read failures (infrastructure — the preview cannot classify
// against an unreadable state).
func PreviewInventoryCSV(ctx context.Context, r io.Reader, current InventoryRepo) (PreviewResult, error) {
	if current == nil {
		return PreviewResult{}, ValidationError("inventory_preview", fmt.Errorf("current-state reader must not be nil"))
	}
	file, err := ParseInventoryCSV(r)
	if err != nil {
		return PreviewResult{}, err
	}

	res := PreviewResult{
		Rows:       file.Rows,
		ErrorCount: len(file.Problems),
		Errors:     file.Problems,
		Warnings:   file.Warnings,
	}

	for i := range file.Assets {
		diff, err := classifyAsset(ctx, &file.Assets[i], current)
		if err != nil {
			return PreviewResult{}, InfraError("inventory_preview", err)
		}
		res.AssetDiffs = append(res.AssetDiffs, diff)
		switch diff.Status {
		case AssetCreated:
			res.AssetsCreated++
		case AssetUpdated:
			res.AssetsUpdated++
		default:
			res.AssetsUnchanged++
		}
		for _, c := range diff.Components {
			switch c.Status {
			case AssetCreated:
				res.ComponentsCreated++
			case AssetUpdated:
				res.ComponentsUpdated++
			default:
				res.ComponentsUnchanged++
			}
		}
	}
	return res, nil
}

// classifyAsset classifies one parsed asset and each of its components
// against the current state.
func classifyAsset(ctx context.Context, asset *InventoryAsset, current InventoryRepo) (AssetDiff, error) {
	diff := AssetDiff{
		Source:     asset.Source,
		ExternalID: asset.ExternalID,
		Lines:      asset.Lines,
		Asset:      *asset,
	}

	cur, found, err := current.CurrentAsset(ctx, asset.Source, asset.ExternalID)
	if err != nil {
		return AssetDiff{}, fmt.Errorf("reading current state of asset (%s, %s): %w", asset.Source, asset.ExternalID, err)
	}
	if !found {
		// No persisted asset: the whole group is created — its
		// components cannot exist without it (a component belongs to
		// exactly one asset, ARCH-003 §1.2).
		diff.Status = AssetCreated
		for _, comp := range asset.Components {
			diff.Components = append(diff.Components, ComponentDiff{Line: comp.Line, Status: AssetCreated, IDs: comp.IDs})
		}
		return diff, nil
	}

	switch {
	case cur.Type != string(asset.Type),
		cur.Name != asset.Name,
		cur.Environment != string(asset.Environment),
		cur.Criticality != string(asset.Criticality),
		cur.Exposure != string(asset.Exposure),
		cur.Owner != asset.Owner:
		diff.Status = AssetUpdated
	default:
		diff.Status = AssetUnchanged
	}

	// Component classification by natural key (UQ (asset_id,
	// natural_key), ARCH-003 §1.3): a parsed component is unchanged when
	// the asset already carries the same natural key with identical raw
	// identifiers, updated when the key exists but a raw identifier
	// differs, created when the key does not exist yet. Derived
	// comparison keys are deterministic functions of the raw identifiers
	// and are not diffed separately.
	byKey := make(map[string]CurrentInventoryComponent, len(cur.Components))
	for _, c := range cur.Components {
		byKey[c.NaturalKey] = c
	}
	for _, comp := range asset.Components {
		state := ComponentDiff{Line: comp.Line, IDs: comp.IDs}
		switch existing, ok := byKey[comp.NaturalKey]; {
		case !ok:
			state.Status = AssetCreated
		case existing.IDs != comp.IDs:
			state.Status = AssetUpdated
		default:
			state.Status = AssetUnchanged
		}
		diff.Components = append(diff.Components, state)
	}
	return diff, nil
}
