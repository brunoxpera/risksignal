# ADR-013 — Bulk file sources: one raw record per file, full sets replaced by TRUNCATE

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 7.1, 8.1, 8.3, 8.4, 13.3, 21.2 |

## Context

Chapter 8.1 step 4 requires storing and hashing raw content unchanged; `raw_records`
carries `unique(source_id, external_id, content_hash)`. For the daily EPSS full set it
was left open what constitutes a raw record. If `external_id` were the CVE ID, the
table would grow by several hundred thousand rows **per day** — at 180 days retention
(chapter 13.3), tens of millions of rows for a source that supplies three numbers per
CVE.

Also open: how the full set is replaced daily without causing table and index bloat.

Additionally, chapter 21.2 points at a source path for the EPSS daily files that is no
longer current.

## Decision

1. **For bulk file sources, a `raw_record` is the file, not the row.** `external_id`
   is the file name or date, the payload is the compressed file, plus a hash. Rows are
   streamed during parsing straight into the normalised tables. This applies to EPSS
   and to the KEV catalogue (chapter 8.3 already describes it that way) and is stated
   generally in chapter 8.1 rather than per adapter.
2. **Two tables for EPSS:**
   - `epss_current` — daily state of all scored CVEs, replaced by `TRUNCATE` + `COPY`
     within **one** transaction
   - `epss_history` — only CVEs with inventory relevance, append-only, fed from the
     same run via the candidate pre-filter from ADR-012
3. **No foreign keys onto `epss_current`.** Prioritisation reads by `cve_id` lookup.
4. **Corrected download URL:** the EPSS daily files are published at
   `https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz`. The EPSS API at
   `api.first.org` remains as described in chapter 8.4 for targeted single lookups and
   diagnostics.

## Rationale

On 1: for a bulk file the evidential value of the raw record lies in the file as a
whole — provenance, fetch time, hash. A per-CVE row copy multiplies data volume
without improving traceability.

On 2: `TRUNCATE` reclaims space immediately and creates no dead tuples. A daily
`DELETE`+`INSERT` over the full set produces bloat that autovacuum can barely keep up
with. In PostgreSQL `TRUNCATE` is transactional, so the swap is atomic.

## Consequences

- `TRUNCATE` takes an ACCESS EXCLUSIVE lock; reads on `epss_current` block for the
  duration of the load. Acceptable given the small user count (chapter 20.2) and a
  load time of seconds — the decision is deliberate and belongs in the operations
  handbook.
- Should the lock window later become a problem, the way out is a partitioned table
  with `ATTACH`/`DETACH PARTITION`. Not to be anticipated in the MVP.
- The actual row count of the daily set is measured once in I2 and recorded in the
  performance evidence, rather than fixed in the concept.
- Chapter 7.1 gains `epss_current` and `epss_history`; chapter 8.1 the general
  statement on bulk file sources; chapter 8.4 the loading strategy and lock window;
  chapter 21.2 the URL.
