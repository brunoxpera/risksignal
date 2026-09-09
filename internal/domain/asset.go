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
