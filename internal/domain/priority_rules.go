package domain

import "fmt"

// PriorityRuleVersion tags the hard-coded ch. 9.3 priority rules below
// (ARCH-001 §1 risk_signals.rule_version). It is the seam I4 replaces with
// the versioned priority_rules table — same contract, versioned
// configuration (ADR-015, ARCH-001 §3 "Deterministic priority for I1b").
const PriorityRuleVersion = "i1b-1"

// Thresholds of the ch. 9.3 rules, kept as constants so the rule table reads
// as documentation.
const (
	// cvssP2Threshold: a high-confidence match is urgent from CVSS >= 9.0.
	cvssP2Threshold = 9.0
	// epssP2Threshold: a high-confidence match is urgent from an EPSS
	// percentile >= 0.95.
	epssP2Threshold = 0.95
)

// Validate checks the cross-field invariants of the factors before they are
// stored with a signal: a known method whose ADR-015-derived confidence
// equals Confidence (method stays authoritative), a known criticality and
// exposure, and in-range CVSS/EPSS values. CVSS is a base score in [0,10];
// EPSS a probability/percentile in [0,1].
func (f PriorityFactors) Validate() error {
	if !f.Method.Valid() {
		return fmt.Errorf("domain: invalid match method %q in priority factors", f.Method)
	}
	derived, ok := f.Method.Confidence()
	if !ok || derived != f.Confidence {
		return fmt.Errorf("domain: confidence %q inconsistent with method %q (ADR-015 derives %q)", f.Confidence, f.Method, derived)
	}
	if !f.Criticality.Valid() {
		return fmt.Errorf("domain: invalid criticality %q in priority factors", f.Criticality)
	}
	if !f.Exposure.Valid() {
		return fmt.Errorf("domain: invalid exposure %q in priority factors", f.Exposure)
	}
	if f.CVSS < 0 || f.CVSS > 10 {
		return fmt.Errorf("domain: cvss %v outside [0,10] in priority factors", f.CVSS)
	}
	if f.EPSS < 0 || f.EPSS > 1 {
		return fmt.Errorf("domain: epss %v outside [0,1] in priority factors", f.EPSS)
	}
	return nil
}

// exposedOrCritical is the asset-context predicate of the ch. 9.3 P1 and
// P2-medium branches: the asset is critical/high criticality or exposed to
// the internet. unknown criticality/exposure never satisfies it — they do
// not upgrade a priority.
func exposedOrCritical(c Criticality, e Exposure) bool {
	return c == CriticalityCritical || c == CriticalityHigh || e == ExposureInternet
}

// ComputePriority implements the deterministic priority rules of ch. 9.3
// ("Deterministische Prioritätsregeln", MVP), rule_version "i1b-1":
//
//	P1  confidence high AND KEV AND (criticality critical/high OR internet)
//	P2  confidence high AND at least one of KEV, CVSS >= 9.0, EPSS >= 0.95
//	    OR confidence medium AND KEV AND critical/exposed context
//	P3  plausible assignment: medium/low or high without a strong urgency
//	    indicator
//	P4  no confirmed inventory assignment or purely informational (candidate
//	    and no_match never claim confirmed impact)
//
// The function is pure and deterministic — same factors, same priority — and
// is the single seam I4 replaces with the priority_rules table. Callers that
// persist the result (NewRiskSignal) must pass factors that Validate accepts;
// ComputePriority itself only reads the fields the rules need.
func ComputePriority(f PriorityFactors) Priority {
	switch f.Confidence {
	case ConfidenceHigh:
		// P1: confirmed high confidence, actively exploited (KEV) and a
		// critical/exposed asset. Immediate notification and SLA clock.
		if f.KEV && exposedOrCritical(f.Criticality, f.Exposure) {
			return PriorityP1
		}
		// P2: confirmed but no P1 context, yet at least one strong urgency
		// indicator (KEV, CVSS >= 9.0, EPSS >= 0.95).
		if f.KEV || f.CVSS >= cvssP2Threshold || f.EPSS >= epssP2Threshold {
			return PriorityP2
		}
		// P3: high confidence without a strong urgency indicator.
		return PriorityP3
	case ConfidenceMedium:
		// P2: medium confidence only reaches P2 with KEV plus a
		// critical/exposed context — the uncertainty stays visible.
		if f.KEV && exposedOrCritical(f.Criticality, f.Exposure) {
			return PriorityP2
		}
		// P3: plausible medium-confidence assignment. Note the ch. 9.3 letter:
		// CVSS/EPSS urgency indicators count only for high confidence.
		return PriorityP3
	default:
		// P4: low (candidate — weak similarity) or none (no_match) means no
		// confirmed inventory assignment; the signal is an observation, not
		// an impact claim (ch. 9.3 P4).
		return PriorityP4
	}
}
