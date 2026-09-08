# Implementation concept — change log v0.1 → v0.2

| Field | Value |
|---|---|
| Source document | RiskSignal implementation concept v0.1, 8 September 2026 (German) |
| Basis | Review walkthrough of seven findings; all decisions confirmed |
| New ADRs | ADR-008 through ADR-015 (`docs/adr/`) |
| Status | To be incorporated into v0.2 |

Chapter-by-chapter list. Functional concept v0.2 remains authoritative; none of these
changes weakens an FR or NFR requirement.

> The concept itself is maintained in German. Chapter titles below are quoted in
> German so they can be located in the source document; everything else is English.

---

## 1. Grundlagen und Architekturentscheide

**1.2 Verbindliche technische Entscheide** — add eight rows:

| ID | Decision |
|---|---|
| ADR-008 | Routing on `net/http` ServeMux, no framework; toolchain pinned to Go 1.27. |
| ADR-009 | Data access through sqlc-generated queries on pgx/v5, without `database/sql`. |
| ADR-010 | Migrations with goose, embedded; plus an own checksum log. |
| ADR-011 | Generated server interfaces from OpenAPI are mandatory (oapi-codegen v2). |
| ADR-012 | Bulk matching runs inventory-driven; candidate pre-filter before job creation. |
| ADR-013 | For bulk file sources a raw record is the file; full sets replaced via TRUNCATE + COPY. |
| ADR-014 | Users are deactivated, never deleted; reversible pseudonymisation with controlled resolution. |
| ADR-015 | Matching is method-led; the score is derived. |

---

## 3. Technologie- und Strukturvorgaben

**3 (intro)** — replace "eine unterstützte stabile Go-Version" with **Go 1.27**, kept
identical across `go.mod`, containerfile and CI.

**3.1 Technologiestack** — tighten four rows:

- *HTTP*: "Go `net/http` with `ServeMux`; middleware chaining in the repository."
- *API contract*: "Documentation, contract tests **and mandatory generated server
  interfaces and types**; client generation optional." (was: "optional generated
  clients/server types")
- *Persistence*: "Access via pgx/v5 and **sqlc-generated**, typed SQL queries."
- *Migrations*: "Forward-only, versioned SQL migrations **using goose, embedded in the
  binaries**."

---

## 4. Laufzeit- und Bereitstellungsarchitektur

**4.4 Deployment-Ablauf**, step 3 — make concrete: migrations run once under an
advisory lock; before each run the hashes of already-applied migrations are verified
against the embedded files, and any divergence aborts (table `schema_migration_log`,
ADR-010).

---

## 6. Domänen- und Datenmodell

**6.2 Wertobjekte und kontrollierte Vokabulare** — new row:

| Value object | Permitted values | Note |
|---|---|---|
| MatchMethod | `exact_identifier`, `container_digest`, `alias_exact_version`, `canonical_product_range`, `product_uncertain_version`, `controlled_alias_only`, `candidate`, `no_match` | Authoritative field; confidence is derived from it (ADR-015). |

---

## 7. Datenbank- und Persistenzkonzept

**7.1 Kernschema** — add six tables:

| Table | Key / central columns | Indexes and constraints |
|---|---|---|
| schema_migration_log | version, file_hash, applied_at, duration_ms | unique(version); divergence blocks startup. |
| epss_current | cve_id, score, percentile, model_version, loaded_at | unique(cve_id); **no foreign keys onto this table**. |
| epss_history | cve_id, observed_on, score, percentile, model_version | unique(cve_id, observed_on); only CVEs with inventory relevance. |
| alias_rules | id, scope, from_value, to_value, version, enabled | unique(scope, from_value, version); versioned, auditable. |
| decision_rules | id, type, target_scope, reason, actor_id, valid_from/until, version | Survives automatic recomputation; auditable. |
| priority_rules | rule_id, version, definition, enabled, effective_from | unique(rule_id, version); stable rule ID. |

---

## 8. Quellenintegration und Verarbeitung

**8.1 Allgemeine Verarbeitungskette** — tighten two steps:

- Step 4, addition: "**For bulk file sources a raw record is the file, not the row.**
  `external_id` is the file name or date, the payload is the compressed file. Rows are
  streamed during parsing." (ADR-013)
- Step 7, replacement: "Determine affected product mappings through a **candidate
  pre-filter against the inventory product index**; only matches create jobs.
  **Bulk runs create `matching.rebuild` instead of individual jobs.**" (ADR-012)

**8.4 FIRST-EPSS-Adapter** — three changes:

- Correct the source path to
  `https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz`; the API at
  `api.first.org` remains for targeted single lookups and diagnostics.
- Add the loading strategy: `epss_current` is replaced via `TRUNCATE` + `COPY` in one
  transaction; `epss_history` is fed from the same run through the candidate
  pre-filter.
- Add the lock window: `TRUNCATE` takes an ACCESS EXCLUSIVE lock, so reads on
  `epss_current` block for the duration of the load. Deliberately accepted given the
  small user count (ch. 20.2); belongs in the operations handbook.

---

## 9. Matching, Priorisierung und SLA

**9.1** — alias handling references the `alias_rules` table (versioned).

**9.2 Matching-Stufen** — convert the table to method-led: column order method →
precondition → confidence → sort rank. Add score semantics: for deterministic methods
a fixed rank derived from the method, **only** for `candidate` a computed similarity
measure. Manual corrections and exclusion rules reference `decision_rules`.

**9.3** — "versionierte Konfiguration mit stabiler Regel-ID" references the
`priority_rules` table.

---

## 10. API-Konzept

**10.1 Konventionen** — add: RFC 9457 problem details are a reusable schema component;
`Idempotency-Key` and `If-Match` are header parameters declared in the OpenAPI
document, not prose only.

**10.2 Ressourcen und Kernendpunkte** — extend the *Audit* row with
`POST /audit-events/{id}/reveal-actor` (permission-gated, self-auditing, ADR-014).

---

## 11. Browseroberfläche und CLI

**11.3 CLI-Befehlsmodell** — extend `maintenance`:

```
risksignal maintenance migrate|retention|recompute|identity-lookup|identity-pseudonymize
```

Both new commands with a mandatory dry run.

---

## 12. Identität, Berechtigungen und Sicherheit

**12 (intro)** — add: "Users are deactivated, never deleted. Their internal ID stays
permanently referenceable so audit entries remain resolvable." (ADR-014)

**12.2 Rollen- und Permission-Matrix** — new row:

| Permission | Analyst | System owner | Admin | Auditor | Product Owner |
|---|---|---|---|---|---|
| audit.reveal_identity | No | No | **No** | Yes | Yes |

This keeps admins consistent with the existing statement that they hold no functional
decision rights — resolving an identity is a functional act, not an operational one.

---

## 13. Audit, Aufbewahrung und Datenschutz

**13.1 Audit-Ereignismodell** — `actor_display_name` is kept as its own, selectively
clearable field, not embedded in a structured blob.

**13.2 Auditpflichtige Aktionen** — add `audit.identity_revealed` (actor, target,
time, mandatory reason).

**13.3 Aufbewahrungsmatrix** — add two data categories:

| Data category | Default | Technical implementation |
|---|---|---|
| Display name in audit | Personal-data period per TD-08 | Field is cleared; displayed as `User #<short-id>`; resolution via `actor_id` remains possible. |
| Free text in audit (`reason`, comments) | Personal-data period per TD-08 | Pseudonymised or removed; may contain personal data of third parties. |

**13.4 Retention-Lauf** — new stage between retention and deletion:
**pseudonymisation**. Reversible by authorised resolution; not anonymisation.

**13.5 Datenschutz und Datenminimierung** — add: because pseudonymisation is
reversible, audit data remains personal data for the full retention period; protection
rests on access control, not on a period. See TD-08.

---

## 14. Hintergrundverarbeitung und Benachrichtigungen

**14.1 Jobtypen** — one new row and one change:

| Job type | Trigger | Idempotency key |
|---|---|---|
| matching.rebuild | Initial import or rule-version change. | rule_version + inventory_snapshot |
| matching.recompute | New evidence, component or rule change. | **hash over sorted vulnerability_id list** + component_scope + rule_version (batch, guide value 500) |

**14.2** — add: `unique(dedupe_key)` stays in effect while a job runs — not only until
it is claimed.

---

## 17. Test-, Qualitäts- und Lieferkonzept

**17.1 Testpyramide**, *Performance* row — add the expectation: a run over 250,000
CVEs and 10,000 assets creates **no job count in the order of magnitude of the CVE
count**; the number of jobs created is measured and recorded as a threshold.

**17.3 CI-Pipeline**, step 3 — make explicit: "OpenAPI validation, **code generation
re-run with diff against the commit**, SQL query, migration and generated-code drift
checks."

---

## 18. Umsetzungsplan und Lieferobjekte

**18.1 Iterationen** — I1 is split into I1a and I1b; I2 runs against a time window and
the NVD full import becomes the exit criterion of I3. Full table in
`docs/plan/iterations.md`.

**18.3 Abhängigkeiten** — add: the inventory product index and the normalisation rules
(ch. 9.1) are needed by I3; the fallback is running I2 on a reduced time window.

---

## 19. Technische Abnahme und Rückverfolgbarkeit

**19.1** — add four technical requirements:

| ID | Technical requirement | Verifiable evidence |
|---|---|---|
| TR-017 | Generated API code is reproducible and does not drift from the schema. | Code-generation diff gate in CI fires on a manual edit. |
| TR-018 | Applied migrations are protected against retroactive modification. | Negative test: an altered migration prevents startup. |
| TR-019 | Bulk imports do not create jobs in the order of magnitude of source records. | Load test counts created jobs against a defined threshold. |
| TR-020 | Audit identity resolution is permission-gated and self-auditing. | Positive/negative test per role; emitted audit event verified. |

**19.2** — add four acceptance tests:

| ID | Check | Procedure | Expected result | Relates to |
|---|---|---|---|---|
| TAT-13 | Codegen drift | Edit a generated handler by hand, run CI. | Build aborts. | TR-017 |
| TAT-14 | Migration checksum | Alter an applied migration file, attempt startup. | Startup aborts with a clear error. | TR-018 |
| TAT-15 | Bulk job cardinality | Run the reference full import, count created jobs. | Job count below threshold; `matching.rebuild` instead of individual jobs. | TR-019 |
| TAT-16 | Identity resolution | Attempt resolution per role; verify a successful resolution. | Only authorised roles; audit event with reason present. | TR-020 |

**19.3 Rückverfolgbarkeit** — extend the *Audit/Retention* row with TAT-16; the
*Betrieb/Qualität* row with TAT-13 through TAT-15.

---

## 20. Risiken, Annahmen und offene Detailentscheide

**20.1**, TRI-04 — extend the countermeasure with candidate pre-filter, batch payload,
`matching.rebuild` and dedupe window until completion (ADR-012).

**20.3 Offene Detailentscheide** — TD-02 is closed (ADR-008 through ADR-011); new entry:

| ID | Decision needed | Latest date | Proposed default |
|---|---|---|---|
| TD-08 | Legal basis and period for personal data in audit records. Because pseudonymisation is reversible, the basis must cover the **full** retention period. | Before I6 | Pseudonymisation 12 months after the person leaves or after `closed_at`, whichever is later. |

---

## 21. Referenzen

**21.2** — correct the FIRST EPSS source path:
`https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz` for the daily files;
`https://api.first.org/epss/` remains for single lookups.

**21.3 Änderungshistorie** — new row:

| Version | Date | Change | Status |
|---|---|---|---|
| 0.2 | 08.09.2026 | Incorporation of the seven review findings; ADR-008 to ADR-015; TD-02 closed, TD-08 added; I1 split. | Entwurf |
