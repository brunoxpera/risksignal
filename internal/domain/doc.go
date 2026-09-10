// Package domain implements the RiskSignal domain model of the walking
// skeleton iterations (implementation concept ch. 6 "Domänen- und
// Datenmodell", ARCH-001 §1, ADR-015; ARCH-002 §3/§4 for the I2 evidence
// pipeline; ARCH-003 for the I3 inventory and matching model).
//
// It contains:
//
//   - the controlled vocabularies of ch. 6.2 (AssetType, Environment,
//     Criticality, Exposure, Confidence, Priority, SignalStatus,
//     MatchMethod, VersionScheme, AliasScope, DecisionRuleType) plus
//     EvidenceType, the ARCH-001 §1 evidences.type vocabulary;
//   - the Vulnerability, Evidence, Match, RiskSignal and Quarantine
//     aggregates of ch. 6.1, shaped to the ARCH-001 §1 data model —
//     Quarantine (ARCH-002 §3/§4) with its guarded
//     new→acknowledged→ready_for_retry→resolved state machine; string UUID
//     identities, no timestamps. created_at/observed_at/occurred_at belong
//     to the application layer behind the injectable clock port
//     (internal/platform/clock), never to the domain;
//   - the I3 inventory aggregates Asset and Component (ARCH-003 §1) with
//     their explicit, guarded deactivation lifecycle and the deterministic
//     component natural_key derivation (naturalkey.go), the pure version
//     semantics of ARCH-003 §2 (version_strategy.go: VersionScheme enum,
//     VersionStrategy comparators for semver/debian/rpm/maven/calver/
//     generic — never lexicographic — plus the NVD range evaluator) and
//     the versioned matching rule value objects AliasRule/DecisionRule
//     with the "a<n>d<m>" ruleset-version derivation;
//   - the ADR-015 method→confidence/score mapping (MatchMethod.Derive), the
//     deterministic candidate similarity of ARCH-003 §3 (similarity.go,
//     scaled into the 1–54 candidate band) and the I4 priority model of
//     ARCH-004 §1: the versioned PriorityRule snapshot with its bounded
//     predicate evaluator (predicate.go, EvaluateRule), the seeded ch. 9.3
//     ruleset (SeedPriorityRules, version PriorityRuleVersion(1)) and the
//     I1b compatibility entry point ComputePriority. The ADR-015 mapping
//     stays hard-coded behind MatchRuleVersion ("i1b-1"); the priority
//     rules no longer are — they are versioned data, with the legacy
//     PriorityRuleVersionI1b ("i1b-1") kept only as history (ADR-015,
//     ARCH-001 §3, ARCH-003 §3, ARCH-004 §1);
//   - the I4 signal state machine and SLA/override value objects (ARCH-004
//     §2–§4): the ch. 6.3 transition matrix (status.go: IsClosed,
//     CanTransition, Transition, IsReopen), the override-survival fields on
//     RiskSignal (Override/Revert, the ADR-015 auto_* mirror), the Comment
//     value object and the SLA value objects SLATarget/SLATimeProfile/
//     SlaClock (pause/resume/fulfil/tighten/reset + effective deadline).
//
// The package is pure by construction: it imports only the Go standard
// library, never an adapter or a generated API package (go-arch-lint gate,
// .go-arch-lint.yml, TR-001) and never reads a clock or a database. All rule
// code is deterministic: same inputs ⇒ same outputs.
package domain
