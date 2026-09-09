package domain

import "testing"

// TestParseEvidenceType covers every allowed I1b EvidenceType value
// (ARCH-001 §1) plus invalid input handling.
func TestParseEvidenceType(t *testing.T) {
	all := []EvidenceType{
		EvidenceTypeSyntheticStatement,
		EvidenceTypeCVSS,
		EvidenceTypeKEV,
		EvidenceTypeEPSS,
	}
	for _, want := range all {
		got, err := ParseEvidenceType(string(want))
		if err != nil {
			t.Errorf("ParseEvidenceType(%q): unexpected error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseEvidenceType(%q) = %q, want %q", want, got, want)
		}
		if !want.Valid() {
			t.Errorf("EvidenceType %q: Valid() = false, want true", want)
		}
	}
	for _, s := range []string{"", "statement", "CVE", "kev ", "nvd", "vuln"} {
		if _, err := ParseEvidenceType(s); err == nil {
			t.Errorf("ParseEvidenceType(%q): want error, got nil", s)
		}
	}
}

// TestNewVulnerability covers the valid shape plus empty-identity handling.
func TestNewVulnerability(t *testing.T) {
	v, err := NewVulnerability("v1", "CVE-2024-0001", "synthetic case one")
	if err != nil {
		t.Fatalf("NewVulnerability: unexpected error: %v", err)
	}
	if v.ID != "v1" || v.CVEID != "CVE-2024-0001" || v.Summary != "synthetic case one" {
		t.Errorf("NewVulnerability = %+v, want id v1 cve CVE-2024-0001", v)
	}

	if _, err := NewVulnerability("", "CVE-2024-0001", "s"); err == nil {
		t.Error("NewVulnerability with empty id: want error, got nil")
	}
	if _, err := NewVulnerability("v1", "", "s"); err == nil {
		t.Error("NewVulnerability with empty cve_id: want error, got nil")
	}
}

// TestNewEvidence exercises every evidence type of the I1b set plus the
// invalid shapes (unknown type, nil value, empty identities/hash).
func TestNewEvidence(t *testing.T) {
	types := []EvidenceType{
		EvidenceTypeSyntheticStatement,
		EvidenceTypeCVSS,
		EvidenceTypeKEV,
		EvidenceTypeEPSS,
	}
	for _, typ := range types {
		e, err := NewEvidence("e1", "v1", "r1", typ, "payload", "hash1")
		if err != nil {
			t.Fatalf("NewEvidence(%q): unexpected error: %v", typ, err)
		}
		if e.Type != typ || e.Value != "payload" || e.ValueHash != "hash1" {
			t.Errorf("NewEvidence(%q) = %+v, want type and value carried", typ, e)
		}
	}

	if _, err := NewEvidence("", "v1", "r1", EvidenceTypeCVSS, 9.8, "h"); err == nil {
		t.Error("NewEvidence with empty id: want error, got nil")
	}
	if _, err := NewEvidence("e1", "", "r1", EvidenceTypeCVSS, 9.8, "h"); err == nil {
		t.Error("NewEvidence with empty vulnerability_id: want error, got nil")
	}
	if _, err := NewEvidence("e1", "v1", "", EvidenceTypeCVSS, 9.8, "h"); err == nil {
		t.Error("NewEvidence with empty raw_record_id: want error, got nil")
	}
	if _, err := NewEvidence("e1", "v1", "r1", EvidenceType("bogus"), 9.8, "h"); err == nil {
		t.Error("NewEvidence with unknown type: want error, got nil")
	}
	if _, err := NewEvidence("e1", "v1", "r1", EvidenceTypeCVSS, nil, "h"); err == nil {
		t.Error("NewEvidence with nil value: want error, got nil")
	}
	if _, err := NewEvidence("e1", "v1", "r1", EvidenceTypeCVSS, 9.8, ""); err == nil {
		t.Error("NewEvidence with empty value_hash: want error, got nil")
	}
}
