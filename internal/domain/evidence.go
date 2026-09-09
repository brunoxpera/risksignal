package domain

import "fmt"

// EvidenceType classifies an immutable source statement (ARCH-001 §1
// evidences.type). The vocabulary is additive: the I1b set mirrors the
// synthetic source's output shapes (synthetic_statement plus the typed
// factor evidences cvss/kev/epss so that prioritisation reads the same
// evidence shapes I2 will feed from NVD/KEV/EPSS); ARCH-002 §3 extends it
// with the I2 evidence types of the NVD/KEV adapters.
type EvidenceType string

// Allowed EvidenceType values (ARCH-001 §1, extended by ARCH-002 §3).
const (
	EvidenceTypeSyntheticStatement EvidenceType = "synthetic_statement"
	EvidenceTypeCVSS               EvidenceType = "cvss"
	EvidenceTypeKEV                EvidenceType = "kev"
	EvidenceTypeEPSS               EvidenceType = "epss"

	// I2 (ARCH-002 §2.1, §2.2, §3): the NVD adapter emits an
	// nvd_statement (the canonical record excerpt of one CVE, hashed) and
	// one reference evidence per advisory link; the KEV adapter
	// historises removals as kev_removed — a new evidence version, never
	// an in-place edit (ch. 6.1).
	EvidenceTypeNVDStatement EvidenceType = "nvd_statement"
	EvidenceTypeReference    EvidenceType = "reference"
	EvidenceTypeKEVRemoved   EvidenceType = "kev_removed"
)

// Valid reports whether t is an allowed EvidenceType value.
func (t EvidenceType) Valid() bool {
	switch t {
	case EvidenceTypeSyntheticStatement,
		EvidenceTypeCVSS,
		EvidenceTypeKEV,
		EvidenceTypeEPSS,
		EvidenceTypeNVDStatement,
		EvidenceTypeReference,
		EvidenceTypeKEVRemoved:
		return true
	}
	return false
}

// ParseEvidenceType parses s into an EvidenceType. Unknown values error.
func ParseEvidenceType(s string) (EvidenceType, error) {
	v := EvidenceType(s)
	if !v.Valid() {
		return "", fmt.Errorf("domain: invalid EvidenceType %q", s)
	}
	return v, nil
}

// Evidence is an immutable source statement about a vulnerability (ch. 6.1,
// ARCH-001 §1 evidences). Corrections never mutate an evidence — they create
// a new row or a new evidence, which is why the aggregate has no setter.
//
// Value carries the source's payload; its concrete shape is defined by the
// source adapters (the synthetic fixture emits a statement, cvss, kev and
// epss evidence per case) and is canonicalised into ValueHash at the
// application layer (SHA-256 of the canonical payload, UQ (raw_record_id,
// type, value_hash)). observed_at comes from the clock port at the
// application layer, not from the domain.
type Evidence struct {
	ID              string // uuid
	VulnerabilityID string
	RawRecordID     string
	Type            EvidenceType
	Value           any // typed source payload; nil is invalid
	ValueHash       string
}

// NewEvidence validates and assembles an Evidence: known type, non-nil
// value and the three identities plus the value hash required by the
// uniqueness constraint.
func NewEvidence(id, vulnerabilityID, rawRecordID string, typ EvidenceType, value any, valueHash string) (Evidence, error) {
	if id == "" {
		return Evidence{}, fmt.Errorf("domain: evidence id must not be empty")
	}
	if vulnerabilityID == "" {
		return Evidence{}, fmt.Errorf("domain: evidence vulnerability_id must not be empty")
	}
	if rawRecordID == "" {
		return Evidence{}, fmt.Errorf("domain: evidence raw_record_id must not be empty")
	}
	if !typ.Valid() {
		return Evidence{}, fmt.Errorf("domain: invalid EvidenceType %q", typ)
	}
	if value == nil {
		return Evidence{}, fmt.Errorf("domain: evidence value must not be nil")
	}
	if valueHash == "" {
		return Evidence{}, fmt.Errorf("domain: evidence value_hash must not be empty")
	}
	return Evidence{
		ID:              id,
		VulnerabilityID: vulnerabilityID,
		RawRecordID:     rawRecordID,
		Type:            typ,
		Value:           value,
		ValueHash:       valueHash,
	}, nil
}
