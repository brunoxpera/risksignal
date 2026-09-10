# Adversarial Review — I4 (Signals, priority & SLA)

- **Phase under review:** I4 — signals, priority & SLA (ARCH-004)
- **Scope:** `64a7ff7..2f070b7` — 35 commits, 100 files, **+18,147 / −485** (re-derived via `git diff --stat`)
- **Reviewer:** orchestrator (`agent:main:risksignal`), adversarial-review discipline
- **Date:** 2026-09-10
- **Reference docs read:** `docs/concept/fachkonzept-v0.2.md` §6, §9; `docs/concept/umsetzungskonzept-v0.2.md` §6.3, §9; `docs/adr/ADR-014`, `ADR-015`; `architecture/ARCH-004.md`

## Summary verdict

**APPROVE WITH REQUIRED FIXES.**

The I4 exit criterion is met and independently re-derived green (P1–P4 reference
matrix, accelerated SLA lifecycle, escalation-exactly-once, atomicity rollback;
full `go test -count=1 ./...` passes). No finding enables an attacker to hide a
vulnerability or forge a priority through the supported command surface. Six
CONCERNs are recorded; two are required fixes, the rest are deferrals or
documentation mismatches.

## Threat model for this change

RiskSignal turns vulnerability matches into prioritised, SLA-bound work items for a
24/7 security team. The adversarial stakes for I4 are: **(1) priority integrity** —
can a signal's P1–P4 class be wrongly elevated (noise/panic) or suppressed (a real
vuln buried as P4)? **(2) SLA-clock integrity** — can a deadline be gamed (pause to
freeze, fulfil without the required action, tighten-loosen) so a P1 avoids
escalation? **(3) state-machine bypass** — can a signal jump off-matrix (e.g.
`new → resolved`) to skip acknowledgement/SLA? **(4) notification injection** — can
attacker-controlled data reach SMTP/webhook or forge paging? **(5) audit integrity**
— can a priority change/override happen without a reason and actor (TR-007, ADR-014)?

## Findings

| ID | Severity | Location | Finding |
|---|---|---|---|
| C-1 | CONCERN | `db/queries/sla_clocks.sql:81` | Resume SQL lacks `resumed_at >= paused_at`; command path bypasses the domain guard |
| C-2 | CONCERN | `internal/application/priority_recompute.go:104` | `PublishPriorityRules` publishes only the fixed seed ruleset (not configurable) |
| C-3 | CONCERN | `internal/adapters/worker/notify.go:381` | notification-clock fulfil is non-atomic with delivery-state update |
| C-4 | CONCERN | `internal/application/signal_triage.go:435` | priority override/revert has no authorization gate (deferred to I5a) |
| C-5 | CONCERN | `internal/adapters/worker/notify.go:126` | notify handler trusts event type for active/passive (no server-side priority re-derivation) |
| C-6 | CONCERN | `internal/domain/predicate.go:189` | a rule node carrying both `all_of` and `any_of` is accepted, contradicting its own doc |

## Finding details

### C-1 — Resume-before-pause is guarded in the domain but bypassed by the command

`domain.SlaClock.Resume` rejects a resume before the pause start
(`internal/domain/sla.go:234`), and a probe confirmed it:

```
func (c SlaClock) Resume(now time.Time) (SlaClock, error) {
    if !c.Paused() { return SlaClock{}, fmt.Errorf(...) }
    if now.Before(c.PausedAt) { return SlaClock{}, fmt.Errorf("...resume %s precedes pause start %s", ...) }
    ...
}
```

But `ResumeSla` (`signal_triage.go:626`) never calls the domain object — it goes
straight to the repo, whose SQL has no guard:

```sql
-- db/queries/sla_clocks.sql:81  ResumeSlaClock
UPDATE sla_clocks SET
    paused_seconds = paused_seconds + (EXTRACT(EPOCH FROM @resumed_at::timestamptz) - EXTRACT(EPOCH FROM paused_at))::bigint,
    paused_at      = NULL
WHERE signal_id = @signal_id AND target = @target AND paused_at IS NOT NULL
RETURNING *;
```

Under backward clock skew (`resumed_at < paused_at`), the `::bigint` difference is
negative, so `paused_seconds` **decreases** — shifting `EffectiveDeadline` earlier
(premature escalation) or, with forward skew, later (missed escalation). The
`now` is the injected clock, so this is skew-gated, not an active exploit.

**Fix:** add `AND @resumed_at >= paused_at` to the SQL (mirroring the domain guard),
or route `ResumeSla` through `domain.SlaClock.Resume` and persist the returned value.

### C-2 — The priority ruleset is not actually configurable

`PublishPriorityRulesInput` carries only `Reason`/`Actor`/`CorrelationID`
(`priority_recompute.go:104`) and the command always publishes
`publishSeedRules(...)` = `domain.SeedPriorityRules()` with the reason/actor stamped
(`priority_recompute.go:170`, `:432`). The concept §6.2 states "Schwellenwerte und
Kombinationen werden konfigurierbar dokumentiert"; I4 ships a hard-coded seed and
"publish" only bumps the version number (triggering a batched recompute). No
operator path can raise the EPSS threshold or reorder rules.

This is safe (no arbitrary-ruleset injection exists) but under-delivers the
configurability the concept promises. **Fix or document:** either accept an operator
rule-set on the command (with the same closed-vocabulary validation) or record an
explicit MVP deferral in ARCH-004.

### C-3 — Notification-clock fulfil is not atomic with the delivery write

`deliverChannel` records `delivered` in one transaction
(`notify.go:277`, `UpdateDelivery`), then `fulfilNotificationClock` fulfils the SLA
clock in a **separate** transaction (`notify.go:381`). If the fulfil tx fails
transiently (→ `Retry`), the redelivery no-ops on the now-terminal notification row
and never re-attempts the fulfil. Already flagged in the DEV-081 review; re-confirmed
here. Impact is reporting accuracy (the `notification` clock does not drive
escalation). **Fix:** fulfil in the same tx as `UpdateDelivery`, or re-attempt fulfil
on redelivery of a terminal row.

### C-4 — Override/revert has no authorization gate

`OverridePriority` (`signal_triage.go:435`) and `RevertPriority` (`:514`) accept any
non-empty actor + reason and apply a priority change. The domain enforces reason and
actor presence, but there is no role/permission check. This is the known I5a deferral
(OIDC + permission matrix), surfaced so it is not mistaken for done.

### C-5 — Notify active/passive trusts the event payload

`NotifyPolicy.active` (`notify.go:126`) treats `signal.escalated` and `reminder`
as always-active regardless of the payload priority, and uppercases an untrusted
`p.Priority` string to decide `signal.created`. A forged outbox event of those types
with a P4 priority would page. The outbox is internal (written atomically by domain
commands), so exposure is low; defense-in-depth would re-derive priority from the
signal row server-side rather than trusting the event.

### C-6 — Rule node accepts both `all_of` and `any_of`

`RuleDefinition` (`predicate.go:189`) documents "either a group (all_of / any_of)",
but `evalRuleNode` (`:323`) accepts a node with both and evaluates it as
`AND(all_of) ∧ OR(any_of)`. A probe confirmed the behaviour (deterministic, not a
bypass). Cosmetic/doc mismatch; **fix:** reject a both-group node in
`validateRuleNode`, or correct the doc.

## Pass evidence (re-derived, not self-reported)

- **Full suite:** `go test -count=1 ./...` → `EXIT=0`, all 27 packages `ok`
  (integration tests ran against real PostgreSQL; none skipped).
- **Lint/gates:** `gofmt -l .` empty; `go vet ./...` clean; `make lint-arch`
  → `OK - No warnings found`; `make lint-golangci` 0 issues (per DEV-082 review).
- **State machine** enforced at the application boundary: `TransitionSignal`
  (`signal_triage.go:185`) calls `domain.Transition` + `TransitionRequiresReason`;
  off-matrix edges are a `ConflictError`, guarded edges without reason a
  `ValidationError`.
- **Predicate evaluator** has a closed vocabulary — unknown op/field/value, empty
  node, and mixed group/atom nodes are errors, never silent defaults
  (`predicate.go`).
- **Override/Revert** enforce double-override rejection, revert-without-override
  rejection, and mandatory reason/actor/time (`risksignal.go`).
- **SLA clocks** are idempotent on fulfil, tighten-only, and reject
  resume-before-pause at the domain layer (`sla.go`).
- **Optimistic locking** is validated (`ExpectedVersion ≥ 1`) and enforced in the
  guarded repo writes (0-row ⇒ conflict).
- **Escalation** is exactly-once via the `MarkEscalated` set-once guard plus the
  `signal.escalated:<id>` dedupe key.
- **Audit atomicity:** every command writes audit + outbox in the same transaction
  as the state change (`appendSignalAudit`/`appendSignalOutbox`).

### Probe output (run during review, then removed)

```
--- PASS: TestProbe_ResumeBeforePauseRejectedAtDomain
    PASS: domain rejects resume-before-pause: domain: sla clock c1 resume
          2026-09-10 12:00:00 +0000 UTC precedes pause start 2026-09-10 12:01:00 +0000 UTC
--- PASS: TestProbe_BothGroupKindsAccepted
    OBSERVED: both all_of+any_of accepted and evaluated as AND(all)∧OR(any)=false
--- PASS: TestProbe_EmptyNodeRejected
    PASS: empty rule node rejected: domain: rule definition is empty (no all_of, any_of or op)
--- PASS: TestProbe_SeedIsDeterministic
    PASS: seed ruleset deterministic, 4 rules, ids P1..P4
```

## Could not verify

- **Authorization end-to-end** — the OIDC/role layer does not exist yet (I5a), so
  "who may override" could not be exercised; only that the domain requires an actor
  string was verifiable.
- **Live SMTP/webhook delivery** — reviewed against the fake/signed-fake adapters
  only; no production mail or webhook target exists in I4 by design.
- **Concurrent-writer safety under a second agent** — the earlier duplicate-agent
  interference was observed but not reproducible in a controlled probe; the tree is
  currently clean and coherent.

## Report location

This file: `docs/reviews/i4-adversarial-review.md` (repo
`/Users/bruno/dev/xpera/riskSignal`). No `reviews/` convention existed in
`CLAUDE.md`/`AGENTS.md`; relocate if the project adopts a different convention.

---

_No findings were fixed during this review. Awaiting instructions on which to
address._
