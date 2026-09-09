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
//     scaled into the 1–54 candidate band) and the ch. 9.3
//     "Deterministische Prioritätsregeln" priority function. All are pure
//     and hard-coded behind the rule-version constants MatchRuleVersion and
//     PriorityRuleVersion ("i1b-1") plus the composite RulesetVersion — the
//     seams the I4 priority_rules table and the I3 rule tables replace
//     without touching the pipeline (ADR-015, ARCH-001 §3, ARCH-003 §3).
//
// The package is pure by construction: it imports only the Go standard
// library, never an adapter or a generated API package (go-arch-lint gate,
// .go-arch-lint.yml, TR-001) and never reads a clock or a database. All rule
// code is deterministic: same inputs ⇒ same outputs.
package domain
