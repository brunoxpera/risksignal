# ADR-015 — Matching is method-led, the score is derived

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 7.1, 9.1–9.3; TR-007, TR-008 |

## Context

Chapter 9.2 defines a score scale (100 / 95 / 90 / 80 / 65 / 55 / 1–54 / 0) with an
associated method and confidence. The prioritisation rules in chapter 9.3, however,
read confidence only — the score appears in no rule. Operationally there is no
difference between 95 and 90; both are `high`.

The numbers therefore suggest a precision that does not exist, and a new method forces
an arbitrary value between two existing ones.

Exception: `1–54 Candidate` is a *range*. There a similarity really is computed. That
is the only place where the score carries genuine information.

## Decision

| Field | Role |
|---|---|
| `method` | **authoritative**, named enum: `exact_identifier`, `container_digest`, `alias_exact_version`, `canonical_product_range`, `product_uncertain_version`, `controlled_alias_only`, `candidate`, `no_match` |
| `confidence` | enum, derived from `method` through a versioned mapping — this is what the rules read |
| `score` | for deterministic methods a fixed sort rank derived from the method; **only** for `candidate` an actually computed similarity measure |

A new method is therefore a new enum value plus two mappings — no argument about
numbers.

## Also: three missing rule tables

Chapter 7.1 lists none of the tables that chapter 9 presupposes. They are added:

- **`decision_rules`** — manual match corrections and exclusion rules from chapter 9.2,
  with reason, scope of validity, author and expiry. They must survive an automatic
  recomputation; without their own table that is precisely what cannot happen.
- **`alias_rules`** — versioned vendor and product aliases from chapter 9.1.
- **`priority_rules`** — versioned rule configuration with a stable rule ID from
  chapter 9.3.

All three are versioned and auditable; all three are referenced by
`matches.rule_version` and `risk_signals.version` respectively. Without them "rule
version" is a field with no counterpart.

## Consequences

- TR-007 and TR-008 remain fully satisfied: method, score, confidence, reasons and rule
  version are still stored.
- `unique(vulnerability_id, component_id, rule_version)` on `matches` stays valid.
- `alias_rules` and `decision_rules` belong to I3, `priority_rules` to I4.
- The alias rules are a prerequisite for the candidate pre-filter in ADR-012 — without
  normalisation there is no usable product index.
