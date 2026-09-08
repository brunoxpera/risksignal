# Iteration plan (as of v0.2)

Replaces chapter 18.1 of the implementation concept. Each iteration delivers a
demonstrable path through API, domain logic, database, audit and at least one
interaction channel. Estimates are made at work-package level, not here.

| Iteration | Focus | Deliverables | Exit criterion |
|---|---|---|---|
| **I1a** | Skeleton & gates | Repository per ch. 3.2, three runnable binaries, Compose with PostgreSQL / OIDC test provider / mail test server, migration runner with checksum log, health and readiness, startup validation, CI stages 1–2, architecture check. | `docker compose up` brings everything up, `/health/ready` is green, CI aborts on a forbidden import, an empty reference database migrates cleanly, and an altered migration prevents startup. |
| **I1b** | Walking skeleton | OpenAPI document, code generation + diff gate, contract test, one record through the chain synthetic source → raw data → evidence → match → signal, two read endpoints, `demo seed`, outbox and audit event atomic for that path. | A synthetic record is imported and displayed as a readable signal over the API; fault injection between domain change and outbox shows a complete rollback. |
| **I2** | Sources & evidence *(time window)* | NVD, KEV and EPSS adapters, raw data, normalisation, idempotency, quarantine, source monitor. **Runs against a bounded time window, not the full data set.** | A twofold reference import produces no duplicates; a failure case is isolated and reprocessable; EPSS daily set loaded and row count measured. |
| **I3** | Inventory & matching | Asset and component model, CSV preview and commit, `alias_rules`, `decision_rules`, version semantics, matching and confidence, **inventory product index and candidate pre-filter**, `matching.rebuild`. | Reference matrix passes for all asset types and match levels; **NVD full import completed with job count below threshold.** |
| **I4** | Signals, priority & SLA | `priority_rules`, P1–P4 rules, state machine, owner, comments, SLA clocks, outbox and notification. | P1–P4 demonstrable including an accelerated SLA test and audit evidence. |
| **I5a** | Identity & authorisation | OIDC integration, role and permission matrix including `audit.reveal_identity`, authorisation at use-case level, local protection mode and online bypass lock. | Role matrix passes; API/CLI channel parity demonstrated; negative startup test with bypass enabled. |
| **I5b** | Web & CLI | Triage interface, administration, complete CLI. | API/web/CLI channel parity passes; UX guardrails from ch. 11.2 met. |
| **I6** | Operations & acceptance | Exports, retention including the pseudonymisation stage, backup/restore, observability, performance, security hardening, private demo. | All mandatory acceptance cases pass; operations and user documentation complete. |

## Changes against chapter 18.1

1. **I1 split.** The gates (architecture boundaries, contract drift, migration
   checksum, atomicity) are cheap while nothing exists and expensive to retrofit. I1a
   delivers no domain logic but all gates. Without the split the exit criterion only
   becomes testable at the very end.
2. **NVD full import moved from I2 to I3.** The candidate pre-filter from ADR-012
   depends on the inventory product index and the normalisation rules, which are only
   built in I3. Running I2 against the full data set would mean hitting the bottleneck
   exactly once, unprotected.
3. **I5 split.** Same pattern as I1: identity and authorisation are the foundation, the
   interfaces build on them. Split apart, the role matrix is testable before the
   interfaces exist.

## Dependencies (extends chapter 18.3)

| Dependency | Needed by | Fallback |
|---|---|---|
| OIDC provider and claims mapping | Start of I5a | Local test provider; online acceptance only with the target provider. |
| NVD API key | I2 | Lower request rate without a key; controlled reference fixtures. |
| Inventory product index and normalisation rules | I3 | I2 stays on a reduced time window. |
| SMTP / webhook target | I4 | Local mail test server and signed fake webhook. |
| Decision TD-08 (legal basis for audit data) | Before I6 | Default from TD-08; MVP runs on synthetic data. |
| Private demo infrastructure | Start of I6 | Local Compose acceptance; online release handled separately. |
| Ticketing target system | After MVP | Port and contract fixtures without a production adapter. |
