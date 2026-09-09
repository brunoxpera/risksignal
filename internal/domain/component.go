package domain

import "fmt"

// ComponentIdentifiers groups the raw, verbatim identifiers of one
// inventory row (ARCH-003 §1.2 components: cpe/purl/image/digest plus the
// I1b vendor/product/version originals). Originals are preserved verbatim
// in the database; the normalised comparison keys (vendor_norm etc.) are
// separate columns computed at write time (ARCH-003 §2 "Originalwerte
// bleiben erhalten").
//
// version, cpe, purl, image and digest are optional per import row;
// vendor/product are required unless cpe/purl/digest carries the identity
// (ARCH-003 §1.3). A digest is immutable and stronger than a mutable image
// tag — that priority is exactly what NaturalKey builds on.
type ComponentIdentifiers struct {
	Vendor  string // original vendor; "" when the identity comes from cpe/purl/digest
	Product string // original product; "" when the identity comes from cpe/purl/digest
	Version string // original version; "" when absent
	CPE     string // original CPE 2.3 string; "" when absent
	PURL    string // original package URL; "" when absent
	Image   string // original image reference registry/repository[:tag][@digest]
	Digest  string // immutable digest (sha256:…); "" when absent
}

// Component is one inventoried component of an asset (ch. 6.1, ARCH-001 §1
// components; ARCH-003 §1.2 extends the I1b aggregate). A component belongs
// to exactly one asset; there is no cross-asset sharing in the MVP.
//
// The field block mirrors the table columns (minus the timestamps, which
// belong to the application layer behind the clock port, package doc). The
// raw identifiers (Vendor/Product/Version/CPE/PURL/Image/Digest) stay
// verbatim; VendorNorm/ProductNorm/VersionNorm are the write-time
// normalised comparison keys (NFKC + trim + lowercase, no alias — aliases
// resolve at match time, ARCH-003 §2); VersionScheme is the inferred
// ordering scheme. NaturalKey is the deterministic import idempotency key
// (UQ (asset_id, natural_key), ARCH-003 §1.2): a SHA-256 of the strongest
// identifier present, prefix-tagged and normalised so an empty or NULL
// identifier never collides and two identifier types never collide.
//
// Like an asset, deactivation is explicit and never implicit (ARCH-003
// §1.3): only the guarded Deactivate transition sets Deactivated, and a
// repeated import that stops carrying a row never deactivates it. Use
// NewComponent to construct with the invariants (natural key derivation,
// identifier presence, scheme validity); the persistence layer scans rows
// back into plain structs.
type Component struct {
	ID      string // uuid
	AssetID string // owning asset

	Vendor  string // original
	Product string // original
	Version string // original; "" when absent

	CPE    string // original; "" when absent
	PURL   string // original; "" when absent
	Image  string // original; "" when absent
	Digest string // original; "" when absent

	VendorNorm    string // normalised comparison key; "" when no vendor
	ProductNorm   string // normalised comparison key; "" when no product
	VersionNorm   string // normalised version for the chosen scheme; "" when absent/not normalisable
	VersionScheme VersionScheme

	NaturalKey  string // SHA-256 hex, strongest present identifier (naturalkey.go)
	Deactivated bool   // soft-deactivate; deactivated_at stamped by the application layer
}

// NewComponent validates and assembles a Component (ARCH-003 §1.2/§1.3).
// The raw identifiers plus the already-normalised comparison keys are
// passed in — normalisation (NFKC/trim/lowercase, scheme inference) is the
// import layer's job (WP-3.04), the domain stores and validates it.
//
// Invariants: id/assetID non-empty; VersionScheme known (unknown included);
// at least one identifier present — cpe, purl, digest or image, or the
// vendor/product pair (mirroring the CSV shape: "vendor/product required
// unless cpe/purl/digest carries the identity"); and the natural key
// derivation succeeds (an all-empty identifier set has no key and is
// rejected instead of hashing empty). A new component is active.
func NewComponent(id, assetID string, ids ComponentIdentifiers, vendorNorm, productNorm, versionNorm string, scheme VersionScheme) (Component, error) {
	if id == "" {
		return Component{}, fmt.Errorf("domain: component id must not be empty")
	}
	if assetID == "" {
		return Component{}, fmt.Errorf("domain: component asset_id must not be empty")
	}
	if !scheme.Valid() {
		return Component{}, fmt.Errorf("domain: invalid VersionScheme %q", scheme)
	}
	if !hasAnyIdentifier(ids) {
		return Component{}, fmt.Errorf("domain: component must carry at least one identifier (cpe, purl, digest, image, or vendor and product)")
	}
	key, err := componentNaturalKey(ids, vendorNorm, productNorm, versionNorm)
	if err != nil {
		return Component{}, fmt.Errorf("domain: component natural key: %w", err)
	}
	return Component{
		ID:            id,
		AssetID:       assetID,
		Vendor:        ids.Vendor,
		Product:       ids.Product,
		Version:       ids.Version,
		CPE:           ids.CPE,
		PURL:          ids.PURL,
		Image:         ids.Image,
		Digest:        ids.Digest,
		VendorNorm:    vendorNorm,
		ProductNorm:   productNorm,
		VersionNorm:   versionNorm,
		VersionScheme: scheme,
		NaturalKey:    key,
	}, nil
}

// hasAnyIdentifier reports whether the raw identifiers satisfy the ARCH-003
// §1.3 presence rule: an identity-carrying cpe/purl/digest (or image, which
// NaturalKey ranks below digest), or the vendor/product pair.
func hasAnyIdentifier(ids ComponentIdentifiers) bool {
	if trim(ids.CPE) != "" || trim(ids.PURL) != "" || trim(ids.Digest) != "" || trim(ids.Image) != "" {
		return true
	}
	return trim(ids.Vendor) != "" && trim(ids.Product) != ""
}

// Deactivate soft-deactivates the component (ARCH-003 §1.2: components stay
// referenceable when deactivated). Like the asset lifecycle, the transition
// is explicit and guarded — a repeated import never deactivates implicitly
// and a deactivated component cannot be deactivated again. The
// deactivated_at timestamp is applied by the application layer.
func (c Component) Deactivate() (Component, error) {
	if c.Deactivated {
		return Component{}, fmt.Errorf("domain: component %s is already deactivated", c.ID)
	}
	c.Deactivated = true
	return c, nil
}
