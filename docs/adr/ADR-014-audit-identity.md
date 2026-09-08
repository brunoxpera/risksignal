# ADR-014 — Identity in the audit trail: deactivate, never delete; reversible pseudonymisation

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 12, 12.2, 13.1–13.5; TD-08 |

## Context

Chapter 13.1 stores `actor_id`, `actor_display_name`, `reason` and `before`/`after`
excerpts; chapter 13.3 keeps audit data for five years from `closed_at`. That is
personal data about employees over a long period. Chapter 13.5 governs data
minimisation at write time, but there is no procedure that reduces the personal
reference over time. Chapter 13.4 knows only dry run, hold and deletion — and for
audit data deletion is the wrong answer, because the record is meant to survive.

## Decision

1. **Users are deactivated, never deleted.** Their ID stays permanently referenceable.
   (Principle; chapter 12 gains the corresponding sentence, mirroring the deactivated
   assets in chapter 6.1.)
2. **Pseudonymisation as its own retention stage** between retention and deletion, to
   be added to chapter 13.4:

   | Field | After personal-data period | After 5 years |
   |---|---|---|
   | `actor_id` | retained | deleted with the event |
   | `actor_display_name` | cleared, displayed as `User #<short-id>` | — |
   | `reason`, comments, free text | pseudonymised or removed | — |
   | action, time, target, rule version | retained | deleted with the event |

3. **Pseudonymisation is reversible.** Resolution runs `actor_id` → `users`. No crypto
   mechanism, no key management — the deactivated user record is the key.
4. **Resolution is controlled:**
   - a dedicated permission `audit.reveal_identity`, **not** part of `audit.read`;
     role matrix in chapter 12.2: auditor and product owner yes, admin no
   - every resolution itself emits an audit event `audit.identity_revealed` carrying
     actor, target, time and a mandatory reason
   - resolution is an explicit call via its own endpoint and its own CLI command,
     never a side effect of rendering a list view
5. Two new maintenance commands under `risksignal maintenance`: find all events for a
   person (subject access request) and pseudonymise — both with a dry run per
   chapter 11.3.

## Rationale

The audit trail stays complete and linkable; the question "who decided what, when"
remains answerable internally for as long as the user record exists. The default view
no longer shows a name.

The only loss compared to the denormalisation in chapter 13.1 is the name *as of the
event*: after a name change, resolution returns the current name. Uncritical for audit
purposes, since the identity is the same.

Free text is the larger risk, not the name. `reason` and comments may contain personal
data of third parties that nobody anticipated; they are therefore treated as their own
data category with their own period, not implicitly as "audit".

## Important limitation

**Reversible pseudonymisation is not anonymisation.** As long as the identity can be
resolved, the audit data remains personal data for the full five years. Protection
rests solely on access control, not on a period after which nobody is identifiable
any more. The legal basis must therefore cover the entire retention period. TD-08 is
worded accordingly.

An unlogged resolution would be worse than no pseudonymisation at all, because it
would feign protection — hence point 4 in full or not at all.

## Regulatory frame

xpera is based in Switzerland; the governing law is the revised Federal Act on Data
Protection (revDSG, in force since 1 September 2023), plus the GDPR where there is an
EU nexus. This is not legal advice; period and legal basis are a business and legal
decision (TD-08). Not blocking for an MVP on synthetic data — blocking before real
operation, see chapter 20.2. Fields and the retention stage are built now so that the
later decision does not force a migration.
