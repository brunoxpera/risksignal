-- 00007_i4_signals_priority_sla.sql — I4 signals, priority & SLA schema
-- (ARCH-004, WP-4.02 / DEV-072).
--
-- Iteration I4 turns the I1b signal stub into a triaged, SLA-tracked workflow
-- object (concept ch. 7.1, ch. 9.3, ch. 6.3). This migration is purely
-- additive: nothing is renamed, no I1b–I3 column or constraint changes
-- meaning, and every new risk_signals column is nullable — so every existing
-- row stays valid and the schema stays forward-only (ADR-010). It carries:
--
--   * priority_rules (§1) — the versioned, copy-on-write ruleset snapshot
--     that replaces the hard-coded I1b ComputePriority switch (ADR-015,
--     ARCH-003 §1.4). Each publish writes a whole 4-row snapshot; a signal
--     references exactly one snapshot through its rule_version, so "den
--     verwendeten Regelstand" (ch. 9.3) is one immutable value. The effective
--     ruleset is MAX(version); the seed below is ruleset version 1, the
--     ch. 9.3 rules reproduced verbatim, so replacing the stub is
--     behaviour-preserving (the reference-matrix test pins this).
--   * comments (§2.2) — append-only signal timeline; every comment is also an
--     audit event (signal.commented) written in the same transaction. No
--     update/delete path.
--   * sla_clocks (§4.1) — the four reaction-time targets per signal
--     (notification/acknowledgement/assessment/decision), their frozen
--     deadline and the pause accounting (paused_seconds/paused_at).
--   * risk_signals extension (§2.1) — auto_priority/override_reason/
--     override_actor_id/override_at mirror the ADR-015 auto_* override
--     survival of matches, and escalated_at records the first P1 escalation
--     (§4.4). The all-or-nothing override CHECK enforces the override
--     invariant at the schema, not only in Go.
--
-- Deferred to I5a (users/roles): owner, override_actor_id and comments.actor_id
-- stay opaque strings; the signals.override/signals.triage permission gate
-- lands with I5a, not I4.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- priority_rules (ARCH-004 §1, concept ch. 7.1): a versioned ruleset snapshot.
-- rule_id is the *stable* rule id (the class the rule produces, P1..P4); every
-- publish inserts a full snapshot with the same 4 rule_ids and version =
-- MAX(version)+1 — UQ (rule_id, version) makes the snapshot immutable and the
-- copy-on-write explicit. definition is the bounded predicate tree (§1.1);
-- enabled makes a disabled rule inert (a disabled P1 demotes to the next
-- matching rule); effective_from/reason/actor_id/created_at come from the
-- injected clock at publish time and are audited (ch. 13.2). The version
-- index serves the effective-snapshot read (WHERE version = MAX(version)).
CREATE TABLE priority_rules (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id        text        NOT NULL,
    version        integer     NOT NULL,
    definition     jsonb       NOT NULL,
    enabled        boolean     NOT NULL DEFAULT true,
    effective_from timestamptz NOT NULL,
    reason         text        NULL,
    actor_id       text        NOT NULL,
    created_at     timestamptz NOT NULL,
    CONSTRAINT priority_rules_rule_id_version_key UNIQUE (rule_id, version)
);

CREATE INDEX priority_rules_version_idx ON priority_rules (version);

COMMENT ON TABLE priority_rules IS
    'Versioned, copy-on-write priority ruleset snapshot (ARCH-004 §1, ch. 7.1): a publish writes the whole P1..P4 snapshot at version = MAX(version)+1; a signal references exactly one snapshot via rule_version';
COMMENT ON COLUMN priority_rules.rule_id IS
    'Stable rule id, one of P1..P4 (the class the rule produces); UQ (rule_id, version) makes each snapshot row immutable';
COMMENT ON COLUMN priority_rules.version IS
    'Ruleset snapshot version, monotonic across all rules; the effective ruleset is MAX(version)';
COMMENT ON COLUMN priority_rules.definition IS
    'Bounded predicate tree (ARCH-004 §1.1): all_of / any_of groups over the closed op {eq,in,ge} · field {confidence,kev,cvss,epss,criticality,exposure} vocabulary — versioned data, never a scripting language';
COMMENT ON COLUMN priority_rules.enabled IS
    'Disabled rules are inert (never deleted — audited config); a disabled P1 demotes to the next matching rule';
COMMENT ON COLUMN priority_rules.effective_from IS
    'Publish instant from the injected clock; the snapshot is effective from here on';
COMMENT ON COLUMN priority_rules.reason IS
    'Why this ruleset changed (audited, ch. 13.2 "Konfigurationsänderung"); NULL allowed';
COMMENT ON COLUMN priority_rules.actor_id IS
    'Publisher principal (audited)';
COMMENT ON COLUMN priority_rules.created_at IS
    'Insert instant from the injected clock (publish time)';

-- Seed ruleset version 1 (ARCH-004 §1.1, §7): the ch. 9.3 rules P1→P4,
-- evaluated first-match-wins with P4 terminal. The definition JSON is the
-- exact serialisation of the domain's SeedPriorityRules() typed predicate
-- trees (internal/domain/priority_rules.go, predicate.go) — P1 confidence
-- high AND kev AND (criticality ∈ {critical,high} OR exposure internet); P2
-- (high AND (kev OR cvss ≥ 9.0 OR epss ≥ 0.95)) OR (medium AND kev AND the
-- same asset-context disjunct); P3 the plausible assignment confidence ∈
-- {high,medium}; P4 the fallback confidence ∈ {low,none}. The reference-matrix
-- test proves this snapshot reproduces the I1b ComputePriority outputs for
-- every factor cell. actor 'system' and the ch. 9.3 reason mirror the domain
-- seed constants; effective_from/created_at are the migration's now() (the
-- seed is the initial publish).
INSERT INTO priority_rules (rule_id, version, definition, enabled, effective_from, reason, actor_id, created_at) VALUES
    ('P1', 1, '{"all_of":[{"op":"in","field":"confidence","values":["high"]},{"op":"eq","field":"kev","value":true},{"any_of":[{"op":"in","field":"criticality","values":["critical","high"]},{"op":"eq","field":"exposure","value":"internet"}]}]}'::jsonb, true, now(), 'ch. 9.3 deterministic priority rules (I4 ruleset v1)', 'system', now()),
    ('P2', 1, '{"any_of":[{"all_of":[{"op":"in","field":"confidence","values":["high"]},{"any_of":[{"op":"eq","field":"kev","value":true},{"op":"ge","field":"cvss","value":9},{"op":"ge","field":"epss","value":0.95}]}]},{"all_of":[{"op":"in","field":"confidence","values":["medium"]},{"op":"eq","field":"kev","value":true},{"any_of":[{"op":"in","field":"criticality","values":["critical","high"]},{"op":"eq","field":"exposure","value":"internet"}]}]}]}'::jsonb, true, now(), 'ch. 9.3 deterministic priority rules (I4 ruleset v1)', 'system', now()),
    ('P3', 1, '{"all_of":[{"op":"in","field":"confidence","values":["high","medium"]}]}'::jsonb, true, now(), 'ch. 9.3 deterministic priority rules (I4 ruleset v1)', 'system', now()),
    ('P4', 1, '{"all_of":[{"op":"in","field":"confidence","values":["low","none"]}]}'::jsonb, true, now(), 'ch. 9.3 deterministic priority rules (I4 ruleset v1)', 'system', now());

-- comments (ARCH-004 §2.2, concept ch. 12.3): the append-only signal timeline.
-- body is length-limited free text, never edited or deleted; every comment is
-- also an audit event (signal.commented) written in the same transaction.
-- actor_id is an opaque principal string until I5a resolves users. The
-- (signal_id, created_at) index serves the ordered timeline read.
CREATE TABLE comments (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id  uuid        NOT NULL,
    actor_id   text        NOT NULL,
    body       text        NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT comments_signal_id_fkey FOREIGN KEY (signal_id) REFERENCES risk_signals (id)
);

CREATE INDEX comments_signal_id_created_at_idx ON comments (signal_id, created_at);

COMMENT ON TABLE comments IS
    'Append-only signal timeline (ARCH-004 §2.2, ch. 12.3): no update/delete path; every comment is also an audit event (signal.commented) written in the same transaction';
COMMENT ON COLUMN comments.signal_id IS
    'The signal this comment belongs to';
COMMENT ON COLUMN comments.actor_id IS
    'Author principal (opaque user id string until I5a resolves users)';
COMMENT ON COLUMN comments.body IS
    'Length-limited free text (ch. 12.3); never edited or deleted';
COMMENT ON COLUMN comments.created_at IS
    'Insert instant from the injected clock';

-- sla_clocks (ARCH-004 §4.1, concept ch. 6.3): the four reaction-time targets
-- per signal — notification, acknowledgement, assessment, decision. deadline_at
-- is started_at + duration(priority, target), frozen at creation; UQ
-- (signal_id, target) allows at most one live clock per target. fulfilled_at
-- NULL = open; paused_seconds accumulates pause time and paused_at is the
-- current pause start (non-NULL while paused) — the one necessary addition to
-- the ch. 7.1 column list, without which the evaluator cannot freeze remaining
-- time during a pause. Pause reason/actor are audit events, not columns; the
-- deadline index drives the sla.evaluate scan and the signal_id index the
-- per-signal clock read.
CREATE TABLE sla_clocks (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id      uuid        NOT NULL,
    target         text        NOT NULL,
    started_at     timestamptz NOT NULL,
    deadline_at    timestamptz NOT NULL,
    fulfilled_at   timestamptz NULL,
    paused_seconds bigint      NOT NULL DEFAULT 0,
    paused_at      timestamptz NULL,
    CONSTRAINT sla_clocks_signal_id_target_key UNIQUE (signal_id, target),
    CONSTRAINT sla_clocks_signal_id_fkey FOREIGN KEY (signal_id) REFERENCES risk_signals (id),
    CONSTRAINT sla_clocks_target_check CHECK (target IN ('notification', 'acknowledgement', 'assessment', 'decision'))
);

CREATE INDEX sla_clocks_deadline_at_idx ON sla_clocks (deadline_at);
CREATE INDEX sla_clocks_signal_id_idx ON sla_clocks (signal_id);

COMMENT ON TABLE sla_clocks IS
    'Per-signal SLA reaction-time clocks (ARCH-004 §4.1, ch. 6.3): one clock per (signal_id, target); the effective deadline is deadline_at + paused_seconds + (now − paused_at while paused)';
COMMENT ON COLUMN sla_clocks.signal_id IS
    'The signal this clock tracks; UQ (signal_id, target) allows at most one live clock per target';
COMMENT ON COLUMN sla_clocks.target IS
    'Reaction-time target: notification | acknowledgement | assessment | decision (ch. 6.3)';
COMMENT ON COLUMN sla_clocks.started_at IS
    'SLA start = commit time of new/upgraded/reopened signal (injected clock); reset on reopen';
COMMENT ON COLUMN sla_clocks.deadline_at IS
    'started_at + duration(priority, target), frozen at creation; tightened on a priority upgrade (ch. 9.4)';
COMMENT ON COLUMN sla_clocks.fulfilled_at IS
    'When the target was met; NULL = open — a fulfilled clock is never re-opened';
COMMENT ON COLUMN sla_clocks.paused_seconds IS
    'Accumulated pause duration in seconds (pauses are not retroactive, ch. 9.4)';
COMMENT ON COLUMN sla_clocks.paused_at IS
    'Current pause start (non-NULL while paused) — needed to freeze remaining time during a pause; NULL while running';

-- risk_signals extension (ARCH-004 §2.1): all five columns are nullable so
-- every I1b–I3 row stays valid (an old row has no override and was never
-- escalated). auto_priority preserves the computed priority when a manual
-- override moved it (the exact ADR-015 mirror of matches.auto_method/
-- auto_confidence/auto_score): the computed starting point stays visible and
-- the override stays reversible. override_reason/override_actor_id/override_at
-- are mandatory on override (ch. 9.3 "nur mit Begründung"; audited); NULL
-- together with auto_priority means "purely computed". escalated_at records
-- the first P1 escalation instant (§4.4); NULL = never escalated.
ALTER TABLE risk_signals
    ADD COLUMN auto_priority     text        NULL,
    ADD COLUMN override_reason   text        NULL,
    ADD COLUMN override_actor_id text        NULL,
    ADD COLUMN override_at       timestamptz NULL,
    ADD COLUMN escalated_at      timestamptz NULL;

-- The override invariant enforced at the schema, not only in Go (ARCH-004
-- §2.1): the four override columns are all-set (an override is in effect —
-- computed value preserved, reason/actor/time recorded) or all-NULL (purely
-- computed, never overridden) — never a partial override. escalated_at is
-- independent of the override quartet and is not part of this CHECK.
ALTER TABLE risk_signals
    ADD CONSTRAINT risk_signals_override_check CHECK (
        (auto_priority IS NULL AND override_reason IS NULL AND override_actor_id IS NULL AND override_at IS NULL)
        OR
        (auto_priority IS NOT NULL AND override_reason IS NOT NULL AND override_actor_id IS NOT NULL AND override_at IS NOT NULL)
    );

COMMENT ON COLUMN risk_signals.auto_priority IS
    'Computed priority preserved when a manual override moved priority (ADR-015 auto_* mirror); NULL = purely computed';
COMMENT ON COLUMN risk_signals.override_reason IS
    'Mandatory reason of a manual override (ch. 9.3 "nur mit Begründung"); NULL = no override';
COMMENT ON COLUMN risk_signals.override_actor_id IS
    'Actor of a manual override (audited); NULL = no override';
COMMENT ON COLUMN risk_signals.override_at IS
    'Instant of a manual override (audited); NULL = no override';
COMMENT ON COLUMN risk_signals.escalated_at IS
    'First P1 escalation instant (ARCH-004 §4.4); NULL = never escalated';
COMMENT ON CONSTRAINT risk_signals_override_check ON risk_signals IS
    'Override invariant (ARCH-004 §2.1): auto_priority, override_reason, override_actor_id and override_at are all-set or all-NULL — never a partial override';
