package domain

import "testing"

// TestParseAssetType covers every allowed AssetType value (ch. 6.2) plus
// invalid input handling.
func TestParseAssetType(t *testing.T) {
	all := []AssetType{
		AssetTypeServerVM,
		AssetTypeApplicationFramework,
		AssetTypeContainerImage,
		AssetTypeNetworkSecurity,
		AssetTypeCloudSaaS,
	}
	for _, want := range all {
		got, err := ParseAssetType(string(want))
		if err != nil {
			t.Errorf("ParseAssetType(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseAssetType(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("AssetType %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "vm", "server", "SERVER_VM", "cloud_saas ", "application"} {
		if _, err := ParseAssetType(s); err == nil {
			t.Errorf("ParseAssetType(%q): want error, got nil", s)
		}
	}
	if AssetType("").Valid() {
		t.Error("zero-value AssetType must not be Valid")
	}
}

// TestParseEnvironment covers every allowed Environment value (ch. 6.2) plus
// invalid input handling.
func TestParseEnvironment(t *testing.T) {
	all := []Environment{
		EnvironmentProduction,
		EnvironmentStaging,
		EnvironmentTest,
		EnvironmentDevelopment,
		EnvironmentUnknown,
	}
	for _, want := range all {
		got, err := ParseEnvironment(string(want))
		if err != nil {
			t.Errorf("ParseEnvironment(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseEnvironment(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("Environment %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "prod", "Production", "staging ", "uat", "qa"} {
		if _, err := ParseEnvironment(s); err == nil {
			t.Errorf("ParseEnvironment(%q): want error, got nil", s)
		}
	}
}

// TestParseCriticality covers every allowed Criticality value (ch. 6.2) plus
// invalid input handling.
func TestParseCriticality(t *testing.T) {
	all := []Criticality{
		CriticalityCritical,
		CriticalityHigh,
		CriticalityNormal,
		CriticalityLow,
		CriticalityUnknown,
	}
	for _, want := range all {
		got, err := ParseCriticality(string(want))
		if err != nil {
			t.Errorf("ParseCriticality(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseCriticality(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("Criticality %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "crit", "HIGH", "severe", "unknown ", "info"} {
		if _, err := ParseCriticality(s); err == nil {
			t.Errorf("ParseCriticality(%q): want error, got nil", s)
		}
	}
}

// TestParseExposure covers every allowed Exposure value (ch. 6.2) plus
// invalid input handling.
func TestParseExposure(t *testing.T) {
	all := []Exposure{
		ExposureInternet,
		ExposureInternal,
		ExposureIsolated,
		ExposureUnknown,
	}
	for _, want := range all {
		got, err := ParseExposure(string(want))
		if err != nil {
			t.Errorf("ParseExposure(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseExposure(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("Exposure %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "public", "INTERNET", "dmz", "internal ", "external"} {
		if _, err := ParseExposure(s); err == nil {
			t.Errorf("ParseExposure(%q): want error, got nil", s)
		}
	}
}

// TestParseConfidence covers every allowed Confidence value (ch. 6.2) plus
// invalid input handling.
func TestParseConfidence(t *testing.T) {
	all := []Confidence{
		ConfidenceHigh,
		ConfidenceMedium,
		ConfidenceLow,
		ConfidenceNone,
	}
	for _, want := range all {
		got, err := ParseConfidence(string(want))
		if err != nil {
			t.Errorf("ParseConfidence(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseConfidence(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("Confidence %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "High", "med", "certain", "unknown", "confident"} {
		if _, err := ParseConfidence(s); err == nil {
			t.Errorf("ParseConfidence(%q): want error, got nil", s)
		}
	}
}

// TestParsePriority covers every allowed Priority value (ch. 6.2) plus
// invalid input handling.
func TestParsePriority(t *testing.T) {
	all := []Priority{
		PriorityP1,
		PriorityP2,
		PriorityP3,
		PriorityP4,
	}
	for _, want := range all {
		got, err := ParsePriority(string(want))
		if err != nil {
			t.Errorf("ParsePriority(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParsePriority(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("Priority %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "P0", "P5", "p1", "P1 ", "1"} {
		if _, err := ParsePriority(s); err == nil {
			t.Errorf("ParsePriority(%q): want error, got nil", s)
		}
	}
}

// TestParseSignalStatus covers every allowed SignalStatus value (ch. 6.2)
// plus invalid input handling.
func TestParseSignalStatus(t *testing.T) {
	all := []SignalStatus{
		SignalStatusNew,
		SignalStatusInReview,
		SignalStatusActionPlanned,
		SignalStatusResolved,
		SignalStatusAccepted,
		SignalStatusNotAffected,
	}
	for _, want := range all {
		got, err := ParseSignalStatus(string(want))
		if err != nil {
			t.Errorf("ParseSignalStatus(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseSignalStatus(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("SignalStatus %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "New", "OPEN", "closed", "new ", "in_review_"} {
		if _, err := ParseSignalStatus(s); err == nil {
			t.Errorf("ParseSignalStatus(%q): want error, got nil", s)
		}
	}
}

// TestParseMatchMethod covers every allowed MatchMethod value (ADR-015,
// ch. 9.2) plus invalid input handling.
func TestParseMatchMethod(t *testing.T) {
	all := []MatchMethod{
		MatchMethodExactIdentifier,
		MatchMethodContainerDigest,
		MatchMethodAliasExactVersion,
		MatchMethodCanonicalProductRange,
		MatchMethodProductUncertainVersion,
		MatchMethodControlledAliasOnly,
		MatchMethodCandidate,
		MatchMethodNoMatch,
	}
	for _, want := range all {
		got, err := ParseMatchMethod(string(want))
		if err != nil {
			t.Errorf("ParseMatchMethod(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseMatchMethod(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("MatchMethod %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "exact", "ExactIdentifier", "exact_identifier ", "purl", "cpe", "unknown"} {
		if _, err := ParseMatchMethod(s); err == nil {
			t.Errorf("ParseMatchMethod(%q): want error, got nil", s)
		}
	}
}
