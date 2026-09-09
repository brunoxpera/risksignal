package domain

import "fmt"

// PriorityFactors are the contributing factors of a signal's priority
// (ARCH-001 §1 risk_signals.factors: confidence, method, cvss, kev, epss,
// criticality, exposure; ch. 9.5 stores them so a later recompute can decide
// whether anything changed). The application layer serialises the struct into
// the factors jsonb column — the snake_case tags below are that mapping.
//
// The ch. 9.3 rules read Confidence, KEV, CVSS, EPSS, Criticality and
// Exposure; Method is carried for traceability and must be consistent with
// Confidence (ADR-015: confidence derives from the method) — NewRiskSignal
// enforces exactly that.
type PriorityFactors struct {
	Method      MatchMethod `json:"method"`
	Confidence  Confidence  `json:"confidence"`
	KEV         bool        `json:"kev"`
	CVSS        float64     `json:"cvss"` // base score in [0,10]; 0 when absent
	EPSS        float64     `json:"epss"` // probability/percentile in [0,1]; 0 when absent
	Criticality Criticality `json:"criticality"`
	Exposure    Exposure    `json:"exposure"`
}

// RiskSignal is one signal per match (ch. 6.1, ARCH-001 §1 risk_signals).
// Priority is derived from the factors by the deterministic ch. 9.3 rules
// (priority_rules.go, tagged PriorityRuleVersion); Status is new on creation
// (I1b always uses new; the ch. 6.3 state machine is I4); Version is the
// optimistic-lock counter of the row, starting at 1.
//
// Owner stays empty until I4 owner assignment; due_at/closed_at and
// created_at are timestamps owned by the application layer (clock port) and
// therefore not part of the aggregate. Use NewRiskSignal to construct with
// the priority/rule-version invariant; the persistence layer scans rows back
// into plain structs.
type RiskSignal struct {
	ID          string // uuid
	MatchID     string // uuid, UNIQUE: exactly one signal per match
	Priority    Priority
	Status      SignalStatus
	Owner       string
	Version     int
	RuleVersion string
	Factors     PriorityFactors
}

// NewRiskSignal validates the factors and assembles a new signal: priority
// derived from the factors by the ch. 9.3 rules, status new (I1b always uses
// new), optimistic-lock version 1 and the priority rule version stamped. The
// caller supplies the signal and match identities; factors must pass
// Validate (method/confidence consistency, in-range CVSS/EPSS, known
// criticality/exposure).
func NewRiskSignal(id, matchID string, f PriorityFactors) (RiskSignal, error) {
	if id == "" {
		return RiskSignal{}, fmt.Errorf("domain: risk signal id must not be empty")
	}
	if matchID == "" {
		return RiskSignal{}, fmt.Errorf("domain: risk signal match_id must not be empty")
	}
	if err := f.Validate(); err != nil {
		return RiskSignal{}, err
	}
	return RiskSignal{
		ID:          id,
		MatchID:     matchID,
		Priority:    ComputePriority(f),
		Status:      SignalStatusNew,
		Owner:       "",
		Version:     1,
		RuleVersion: PriorityRuleVersion,
		Factors:     f,
	}, nil
}
