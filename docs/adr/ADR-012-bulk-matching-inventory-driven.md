# ADR-012 — Bulk matching is inventory-driven, not CVE-driven

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 8.1, 9, 14.1, 17.1; TRI-04 |

## Context

Chapter 8.1 step 7 has the right instinct — "no global recomputation without cause".
Chapter 14.1, however, sets the idempotency key of `matching.recompute` to
`vulnerability_id + component_scope + rule_version`, i.e. one job per CVE. On first
import every CVE is new; at a scale of several hundred thousand published CVEs, an
equivalent number of jobs would be created.

The performance test in chapter 17.1 (250,000 CVEs, 10,000 assets) targets exactly
this case, but the concept does not say how it is meant to pass. TRI-04 names only
generic countermeasures.

## Decision

1. **Candidate pre-filter before job creation.** An index over the normalised
   `vendor`/`product` of components. After normalisation, a semi-join decides which
   vulnerabilities have any candidate in the inventory at all. Only those create jobs.
2. **New job type `matching.rebuild`.** Initial import and rule-version changes create
   exactly one job that walks the components inventory-driven in bounded batches.
   Idempotency key: `rule_version + inventory_snapshot`.
3. **Batch payload for `matching.recompute`.** A capped list (guide value 500) instead
   of one vulnerability per job. Idempotency key: hash over the sorted ID list plus
   `rule_version`.
4. **Dedupe window until completion.** The `unique(dedupe_key)` from chapter 7.1 stays
   in effect while a job runs — not only until it is claimed.

## Rationale

In bulk, the favourable direction inverts: 10,000 assets with a few hundred distinct
normalised products are two orders of magnitude fewer than the total CVE population.
Point 1 reduces job creation in incremental operation, point 2 avoids it entirely in
bulk, point 3 cuts queue row count, and point 4 prevents double enqueueing when
source runs overlap.

## Consequences

- The product index on `components` and the normalisation rules in chapter 9.1 are
  prerequisites. They belong to I3.
- For the plan this means: **I2 runs against a time window, not the full data set.
  The NVD full import becomes the exit criterion of I3.**
- The same pre-filter feeds `epss_history` (ADR-013). Build once, use twice.
- Chapter 14.1 gains `matching.rebuild`; chapter 8.1 step 7 is made precise; the
  TRI-04 countermeasure is extended with pre-filter and batching.
