// Package domain implements the RiskSignal domain model of the I1b walking
// skeleton (implementation concept ch. 6 "Domänen- und Datenmodell",
// ARCH-001 §1, ADR-015).
//
// It contains:
//
//   - the controlled vocabularies of ch. 6.2 (AssetType, Environment,
//     Criticality, Exposure, Confidence, Priority, SignalStatus, MatchMethod)
//     plus EvidenceType, the ARCH-001 §1 evidences.type vocabulary;
//   - the Vulnerability, Evidence, Match, RiskSignal and Quarantine
//     aggregates of ch. 6.1, shaped to the ARCH-001 §1 data model —
//     Quarantine (ARCH-002 §3/§4) with its guarded
//     new→acknowledged→ready_for_retry→resolved state machine; string UUID
//     identities, no timestamps. created_at/observed_at/occurred_at belong
//     to the application layer behind the injectable clock port
//     (internal/platform/clock), never to the domain;
//   - the ADR-015 method→confidence/score mapping and the ch. 9.3
//     "Deterministische Prioritätsregeln" priority function. Both are pure and
//     hard-coded behind the rule-version constants MatchRuleVersion and
//     PriorityRuleVersion ("i1b-1") — the single seam the I4 priority_rules
//     table replaces without touching the pipeline (ADR-015, ARCH-001 §3).
//
// The package is pure by construction: it imports only the Go standard
// library, never an adapter or a generated API package (go-arch-lint gate,
// .go-arch-lint.yml, TR-001) and never reads a clock or a database. All rule
// code is deterministic: same inputs ⇒ same outputs.
package domain
