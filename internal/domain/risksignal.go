package domain

import (
	"fmt"
	"time"
)

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
// Priority is the *effective* value: the currently applied class, derived
// from the factors by the deterministic ch. 9.3 rules (SeedPriorityRules,
// tagged with the ruleset rule_version) unless a manual override replaced it
// (ARCH-004 §3). Status is new on creation; the ch. 6.3 state machine guards
// every later change (status.go). Version is the optimistic-lock counter of
// the row, starting at 1.
//
// Owner stays empty until owner assignment; due_at/closed_at and created_at
// are timestamps owned by the application layer (clock port) and therefore
// not part of the aggregate. Use NewRiskSignal to construct with the
// priority/rule-version invariant; the persistence layer scans rows back
// into plain structs.
//
// AutoPriority + OverrideReason/OverrideActorID/OverrideAt are the
// override-survival fields (ADR-015 mirror, ARCH-004 §3). A manual override
// moves the computed value into AutoPriority and stamps reason/actor/time —
// the four override columns are all-set or all-NULL (the schema CHECK
// mirrors this invariant). AutoPriority is nil exactly when no override is
// active; use Override/Revert, never a raw field write. A priority.recompute
// updates AutoPriority only for an overridden signal, so the human decision
// always wins.
type RiskSignal struct {
	ID          string // uuid
	MatchID     string // uuid, UNIQUE: exactly one signal per match
	Priority    Priority
	Status      SignalStatus
	Owner       string
	Version     int
	RuleVersion string
	Factors     PriorityFactors

	// AutoPriority preserves the computed priority when an override is
	// active; nil = purely computed. It mirrors auto_priority.
	AutoPriority *Priority
	// OverrideReason/OverrideActorID/OverrideAt record the audited manual
	// override (mandatory together on override); zero/empty when none is
	// active.
	OverrideReason  string
	OverrideActorID string
	OverrideAt      time.Time
}

// NewRiskSignal validates the factors and assembles a new signal: priority
// derived from the factors by the ch. 9.3 seed ruleset, status new,
// optimistic-lock version 1 and the I1b rule version stamped (the effective
// version is read through the PriorityRuleRepo port by the I4 create path,
// WP-4.04). The caller supplies the signal and match identities; factors must
// pass Validate (method/confidence consistency, in-range CVSS/EPSS, known
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
		RuleVersion: PriorityRuleVersionI1b,
		Factors:     f,
	}, nil
}

// Overridden reports whether a manual priority override is active.
func (s RiskSignal) Overridden() bool {
	return s.AutoPriority != nil
}

// Override replaces the effective priority with chosen, preserving the
// computed value in AutoPriority and stamping reason/actor/time — the
// ADR-015 auto_* mirror (ARCH-004 §3). reason and actorID are mandatory
// (ch. 9.3 "nur mit Begründung", audited). A signal already overridden must
// be reverted first; an override is a guarded command with one audit event,
// never a silent write. The returned signal is the updated value.
func (s RiskSignal) Override(priority Priority, reason, actorID string, at time.Time) (RiskSignal, error) {
	if !priority.Valid() {
		return RiskSignal{}, fmt.Errorf("domain: risk signal override: invalid Priority %q", priority)
	}
	if reason == "" {
		return RiskSignal{}, fmt.Errorf("domain: risk signal override: reason must not be empty")
	}
	if actorID == "" {
		return RiskSignal{}, fmt.Errorf("domain: risk signal override: actor_id must not be empty")
	}
	if at.IsZero() {
		return RiskSignal{}, fmt.Errorf("domain: risk signal override: override instant must not be zero")
	}
	if s.Overridden() {
		return RiskSignal{}, fmt.Errorf("domain: risk signal %s is already overridden (revert first)", s.ID)
	}
	auto := s.Priority
	s.AutoPriority = &auto
	s.Priority = priority
	s.OverrideReason = reason
	s.OverrideActorID = actorID
	s.OverrideAt = at
	return s, nil
}

// Revert restores the computed priority from AutoPriority and clears the
// four override columns (one audited command, not a silent write). Reverting
// a signal without an active override is an error.
func (s RiskSignal) Revert() (RiskSignal, error) {
	if !s.Overridden() {
		return RiskSignal{}, fmt.Errorf("domain: risk signal %s has no override to revert", s.ID)
	}
	s.Priority = *s.AutoPriority
	s.AutoPriority = nil
	s.OverrideReason = ""
	s.OverrideActorID = ""
	s.OverrideAt = time.Time{}
	return s, nil
}
