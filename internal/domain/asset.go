package domain

import "fmt"

// AssetType classifies an inventory asset (ch. 6.2, ARCH-001 §1 assets.type).
// The vocabulary is extensible by migration and API versioning.
type AssetType string

// Allowed AssetType values (ch. 6.2).
const (
	AssetTypeServerVM             AssetType = "server_vm"
	AssetTypeApplicationFramework AssetType = "application_framework"
	AssetTypeContainerImage       AssetType = "container_image"
	AssetTypeNetworkSecurity      AssetType = "network_security"
	AssetTypeCloudSaaS            AssetType = "cloud_saas"
)

// Valid reports whether t is an allowed AssetType value.
func (t AssetType) Valid() bool {
	switch t {
	case AssetTypeServerVM,
		AssetTypeApplicationFramework,
		AssetTypeContainerImage,
		AssetTypeNetworkSecurity,
		AssetTypeCloudSaaS:
		return true
	}
	return false
}

// ParseAssetType parses s into an AssetType. Unknown values error so a typo
// or an out-of-date source cannot silently pass through the boundary.
func ParseAssetType(s string) (AssetType, error) {
	v := AssetType(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid AssetType %q", s)
	}
	return v, nil
}

// Environment is the runtime environment of an asset (ch. 6.2, ARCH-001 §1
// assets.environment). Production does not raise priority by itself — it is
// visible context only — which is why no ch. 9.3 rule reads it.
type Environment string

// Allowed Environment values (ch. 6.2).
const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentTest        Environment = "test"
	EnvironmentDevelopment Environment = "development"
	EnvironmentUnknown     Environment = "unknown"
)

// Valid reports whether e is an allowed Environment value.
func (e Environment) Valid() bool {
	switch e {
	case EnvironmentProduction,
		EnvironmentStaging,
		EnvironmentTest,
		EnvironmentDevelopment,
		EnvironmentUnknown:
		return true
	}
	return false
}

// ParseEnvironment parses s into an Environment. Unknown values error.
func ParseEnvironment(s string) (Environment, error) {
	v := Environment(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid Environment %q", s)
	}
	return v, nil
}

// Criticality is the business criticality of an asset (ch. 6.2, ARCH-001 §1
// assets.criticality). Unknown criticality triggers a data-quality warning at
// the application layer and never upgrades a priority by itself.
type Criticality string

// Allowed Criticality values (ch. 6.2).
const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityNormal   Criticality = "normal"
	CriticalityLow      Criticality = "low"
	CriticalityUnknown  Criticality = "unknown"
)

// Valid reports whether c is an allowed Criticality value.
func (c Criticality) Valid() bool {
	switch c {
	case CriticalityCritical,
		CriticalityHigh,
		CriticalityNormal,
		CriticalityLow,
		CriticalityUnknown:
		return true
	}
	return false
}

// ParseCriticality parses s into a Criticality. Unknown values error.
func ParseCriticality(s string) (Criticality, error) {
	v := Criticality(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid Criticality %q", s)
	}
	return v, nil
}

// Exposure is how exposed an asset is to the internet (ch. 6.2, ARCH-001 §1
// assets.exposure). Unknown exposure must never be interpreted as internal —
// it simply is not internet and therefore does not satisfy the internet part
// of the ch. 9.3 context predicate.
type Exposure string

// Allowed Exposure values (ch. 6.2).
const (
	ExposureInternet Exposure = "internet"
	ExposureInternal Exposure = "internal"
	ExposureIsolated Exposure = "isolated"
	ExposureUnknown  Exposure = "unknown"
)

// Valid reports whether e is an allowed Exposure value.
func (e Exposure) Valid() bool {
	switch e {
	case ExposureInternet,
		ExposureInternal,
		ExposureIsolated,
		ExposureUnknown:
		return true
	}
	return false
}

// ParseExposure parses s into an Exposure. Unknown values error.
func ParseExposure(s string) (Exposure, error) {
	v := Exposure(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid Exposure %q", s)
	}
	return v, nil
}

// Asset is an inventoried asset (ch. 6.1, ARCH-001 §1 assets; ARCH-003 §1.1
// extends the I1b aggregate). The field block mirrors the table columns
// (minus the timestamps, which belong to the application layer behind the
// clock port, package doc): external_id/source are the import idempotency
// key UQ (source, external_id), the vocabulary fields use the enums above.
//
// Deactivation is explicit and never implicit: only the guarded Deactivate
// transition sets Deactivated (the deactivated_at stamp is applied by the
// application layer), so an import that stops carrying an asset can never
// accidentally deactivate it (ARCH-003 §1.3). Verified records the last
// manual data-quality verification (ch. 11.1 "letzte Verifikation",
// ARCH-003 §1.1 verified_at); it is informational, never a state gate.
// Use NewAsset to construct with the invariants; the persistence layer
// scans rows back into plain structs.
type Asset struct {
	ID          string // uuid
	ExternalID  string // import idempotency key half (UQ source, external_id)
	Source      string // import idempotency key half
	Type        AssetType
	Name        string
	Environment Environment
	Criticality Criticality
	Exposure    Exposure
	Owner       string // "" when unassigned

	Deactivated bool // soft-deactivate; deactivated_at stamped by the application layer
	Verified    bool // last manual data-quality verification; verified_at stamped there too
}

// NewAsset validates and assembles an Asset (ARCH-001 §1 assets). id,
// externalID, source and name are required (NOT NULL columns); the type and
// the three context vocabularies must be known values (unknown enum values
// are still representable on the boundary as typed "unknown" members, but
// a typo never passes silently). A new asset is active (Deactivated false)
// and not yet verified.
func NewAsset(id, externalID, source, name, owner string, typ AssetType, env Environment, crit Criticality, exp Exposure) (Asset, error) {
	if id == "" {
		return Asset{}, fmt.Errorf("domain: asset id must not be empty")
	}
	if externalID == "" {
		return Asset{}, fmt.Errorf("domain: asset external_id must not be empty")
	}
	if source == "" {
		return Asset{}, fmt.Errorf("domain: asset source must not be empty")
	}
	if name == "" {
		return Asset{}, fmt.Errorf("domain: asset name must not be empty")
	}
	if !typ.Valid() {
		return Asset{}, fmt.Errorf("domain: invalid AssetType %q", typ)
	}
	if !env.Valid() {
		return Asset{}, fmt.Errorf("domain: invalid Environment %q", env)
	}
	if !crit.Valid() {
		return Asset{}, fmt.Errorf("domain: invalid Criticality %q", crit)
	}
	if !exp.Valid() {
		return Asset{}, fmt.Errorf("domain: invalid Exposure %q", exp)
	}
	return Asset{
		ID:          id,
		ExternalID:  externalID,
		Source:      source,
		Type:        typ,
		Name:        name,
		Environment: env,
		Criticality: crit,
		Exposure:    exp,
		Owner:       owner,
	}, nil
}

// Deactivate soft-deactivates the asset (ARCH-003 §1.1: "soft-deactivate,
// never delete — deactivated assets stay historically referenceable"). The
// transition is explicit and guarded: an already-deactivated asset cannot
// be deactivated again (a repeated import must not silently re-stamp the
// lifecycle — deactivation is an operator action). The deactivated_at
// timestamp is applied by the application layer.
func (a Asset) Deactivate() (Asset, error) {
	if a.Deactivated {
		return Asset{}, fmt.Errorf("domain: asset %s is already deactivated", a.ID)
	}
	a.Deactivated = true
	return a, nil
}

// Verify records a manual data-quality verification (ARCH-003 §1.1
// verified_at: "last manual data-quality verification; informational in
// I3"). Verification is repeatable — every operator check re-verifies the
// row — and is independent of the deactivation state.
func (a Asset) Verify() (Asset, error) {
	a.Verified = true
	return a, nil
}
