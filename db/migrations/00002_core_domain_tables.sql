-- 00002_core_domain_tables.sql — I1b walking-skeleton core schema (ARCH-001 §1,
-- WP-1b.02).
--
-- Creates exactly the tables the I1b vertical slice needs, shaped so that
-- I2/I3/I4 reuse them rather than migrate them: sources … risk_signals.
-- Columns, types, constraints and indexes match ARCH-001 §1 verbatim.
--
-- Identifier rules (implementation concept ch. 7.2, ARCH-001 §1): uuid
-- primary keys via gen_random_uuid() (core PostgreSQL since 13; the
-- environment runs postgres:16), external IDs stored separately, every
-- timestamp timestamptz. No table carries a foreign key onto a table that
-- does not exist in I1b.
--
-- audit_events and outbox are deliberately NOT here — they are the next
-- task (WP-1b.03, migration 00003). Nothing I2/I3/I4-shaped enters this
-- migration either: no epss_*, no alias/decision/priority rules, no users,
-- no quarantine, no description/CVSS/reference columns on vulnerabilities,
-- no cpe/purl/image/digest on components.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- sources — the synthetic source is a real, configured source (ch. 8.5: it
-- implements the same adapter contract as later adapters). UQ (type, name).
CREATE TABLE sources (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    type       text        NOT NULL,
    name       text        NOT NULL,
    endpoint   text        NULL,
    schedule   text        NULL,
    enabled    boolean     NOT NULL DEFAULT true,
    cursor     jsonb       NULL,
    config     jsonb       NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sources_type_name_key UNIQUE (type, name)
);

COMMENT ON TABLE sources IS
    'Configured sources feeding the pipeline; the I1b synthetic source is one row here (ARCH-001 §1)';
COMMENT ON COLUMN sources.endpoint IS
    'Unused by the synthetic source; reserved for HTTP sources (I2+)';
COMMENT ON COLUMN sources.schedule IS
    'Reserved (concept ch. 8.1); the I1b source is operator-triggered only';
COMMENT ON COLUMN sources.cursor IS
    'Reserved; the synthetic source is a single deterministic document per run and has no cursor';

-- source_runs — one row per synthetic run (ch. 6.1 SourceRun): exactly one
-- end state, counters advanced only on success. IX (source_id, started_at DESC).
CREATE TABLE source_runs (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id   uuid        NOT NULL REFERENCES sources (id),
    started_at  timestamptz NOT NULL,
    finished_at timestamptz NULL,
    status      text        NOT NULL,
    counters    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    error       text        NULL,
    CONSTRAINT source_runs_status_check CHECK (status IN ('running', 'succeeded', 'failed'))
);

CREATE INDEX source_runs_source_id_started_at_idx ON source_runs (source_id, started_at DESC);

COMMENT ON TABLE source_runs IS
    'One row per source run; counters (records, matched, signals) advance only on success (ARCH-001 §1)';
COMMENT ON COLUMN source_runs.status IS
    'running | succeeded | failed — exactly one end state per run (concept ch. 6.1)';
COMMENT ON COLUMN source_runs.counters IS
    'Run counters {records, matched, signals}; committed with the success status';

-- raw_records — the unchanged synthetic document (ch. 8.1 step 4; ADR-013:
-- for bulk sources a raw record is the file/document, not the row — the
-- synthetic source is a single deterministic document per run).
-- UQ (source_id, external_id, content_hash).
CREATE TABLE raw_records (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id    uuid        NOT NULL REFERENCES sources (id),
    external_id  text        NOT NULL,
    content_hash text        NOT NULL,
    payload      jsonb       NOT NULL,
    fetched_at   timestamptz NOT NULL,
    CONSTRAINT raw_records_source_id_external_id_content_hash_key UNIQUE (source_id, external_id, content_hash)
);

COMMENT ON TABLE raw_records IS
    'Raw source documents, stored unchanged and hashed (ch. 8.1 step 4); the natural key makes ingest idempotent (ARCH-001 §1)';
COMMENT ON COLUMN raw_records.external_id IS
    'Stable external document name, e.g. synthetic-reference or per run';
COMMENT ON COLUMN raw_records.content_hash IS
    'SHA-256 hex of the canonical payload';

-- vulnerabilities — normalized vulnerability (ch. 7.1). I1b carries only the
-- identity + summary fields; the full NVD description/CVSS-metrics/references
-- arrive with I2. UQ (cve_id).
CREATE TABLE vulnerabilities (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id       text        NOT NULL,
    summary      text        NOT NULL,
    published_at timestamptz NOT NULL,
    modified_at  timestamptz NULL,
    CONSTRAINT vulnerabilities_cve_id_key UNIQUE (cve_id)
);

COMMENT ON TABLE vulnerabilities IS
    'Normalized vulnerabilities; I1b identity + summary only (ARCH-001 §1), full NVD fields arrive with I2';

-- evidences — immutable source statements (ch. 6.1 Evidence): one
-- synthetic_statement evidence per case, plus typed factor evidences (cvss,
-- kev, epss) so prioritisation reads the same evidence shapes I2 will feed.
-- UQ (raw_record_id, type, value_hash).
CREATE TABLE evidences (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id uuid        NOT NULL REFERENCES vulnerabilities (id),
    raw_record_id    uuid        NOT NULL REFERENCES raw_records (id),
    type             text        NOT NULL,
    value            jsonb       NOT NULL,
    value_hash       text        NOT NULL,
    observed_at      timestamptz NOT NULL,
    CONSTRAINT evidences_raw_record_id_type_value_hash_key UNIQUE (raw_record_id, type, value_hash)
);

COMMENT ON TABLE evidences IS
    'Immutable source statements per vulnerability (ch. 6.1); typed: synthetic_statement | cvss | kev | epss (ARCH-001 §1)';
COMMENT ON COLUMN evidences.value_hash IS
    'SHA-256 of the canonical value';

-- assets — minimal inventory parent (ch. 6.1). Only the fields the walking
-- skeleton needs to compute a priority and to render a signal; the full
-- lifecycle, data-quality and verification model is I3.
-- UQ (source, external_id).
CREATE TABLE assets (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id  text        NOT NULL,
    source       text        NOT NULL,
    type         text        NOT NULL,
    name         text        NOT NULL,
    environment  text        NOT NULL,
    criticality  text        NOT NULL,
    exposure     text        NOT NULL,
    owner        text        NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT assets_source_external_id_key UNIQUE (source, external_id)
);

COMMENT ON TABLE assets IS
    'Inventory assets (ch. 6.1); type/environment/criticality/exposure hold the domain enum values (ARCH-001 §1)';

-- components — one component per asset (ch. 6.1). I1b keeps
-- vendor/product/version only; CPE, purl, image/digest, alias handling and
-- the normalised product index are I3. IX (vendor, product) is plain for
-- now; the I3 normalised index replaces it.
CREATE TABLE components (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id   uuid        NOT NULL REFERENCES assets (id),
    vendor     text        NOT NULL,
    product    text        NOT NULL,
    version    text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX components_vendor_product_idx ON components (vendor, product);

COMMENT ON TABLE components IS
    'One component row per asset (ch. 6.1); vendor/product/version only in I1b (ARCH-001 §1), CPE/purl/digest arrive with I3';

-- matches — method-led match (ADR-015): method authoritative, confidence
-- derived from it, score the derived sort rank.
-- UQ (vulnerability_id, component_id, rule_version).
CREATE TABLE matches (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id uuid        NOT NULL REFERENCES vulnerabilities (id),
    component_id     uuid        NOT NULL REFERENCES components (id),
    method           text        NOT NULL,
    score            integer     NOT NULL,
    confidence       text        NOT NULL,
    rule_version     text        NOT NULL,
    created_at       timestamptz NOT NULL,
    CONSTRAINT matches_vulnerability_id_component_id_rule_version_key UNIQUE (vulnerability_id, component_id, rule_version)
);

COMMENT ON TABLE matches IS
    'Method-led vulnerability-to-component matches (ADR-015); the natural key makes re-runs idempotent (ARCH-001 §1)';
COMMENT ON COLUMN matches.method IS
    'MatchMethod enum value (ADR-015); the authoritative field of the match';
COMMENT ON COLUMN matches.score IS
    'Derived sort rank; only candidate computes a real value';
COMMENT ON COLUMN matches.confidence IS
    'Confidence enum value derived from method, never stored independently';

-- risk_signals — one signal per match (ch. 6.1). Optimistic locking via
-- version (ch. 7.3). factors stores the contributing factors so a later
-- recompute can decide whether anything changed (ch. 9.5).
-- match_id unique: a match has at most one signal (command-level idempotency).
CREATE TABLE risk_signals (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    match_id     uuid        NOT NULL,
    priority     text        NOT NULL,
    status       text        NOT NULL DEFAULT 'new',
    owner        text        NULL,
    due_at       timestamptz NULL,
    closed_at    timestamptz NULL,
    version      integer     NOT NULL DEFAULT 1,
    rule_version text        NOT NULL,
    factors      jsonb       NOT NULL,
    created_at   timestamptz NOT NULL,
    CONSTRAINT risk_signals_match_id_key UNIQUE (match_id),
    CONSTRAINT risk_signals_match_id_fkey FOREIGN KEY (match_id) REFERENCES matches (id)
);

CREATE INDEX risk_signals_priority_status_idx ON risk_signals (priority, status);

COMMENT ON TABLE risk_signals IS
    'One signal per match (ch. 6.1); priority P1-P4, status new in I1b, version is the optimistic-lock token (ARCH-001 §1)';
COMMENT ON COLUMN risk_signals.priority IS
    'Priority enum value P1-P4; derived by the ch. 9.3 rules (rule_version tags which ruleset produced it)';
COMMENT ON COLUMN risk_signals.status IS
    'SignalStatus enum; I1b always creates signals with status new (full state machine is I4)';
COMMENT ON COLUMN risk_signals.version IS
    'Optimistic-lock counter; every update must carry the version the client read (ch. 7.3)';
COMMENT ON COLUMN risk_signals.factors IS
    'Contributing factors (confidence, method, cvss, kev, epss, criticality, exposure) so a recompute can detect changes (ch. 9.5)';
COMMENT ON COLUMN risk_signals.due_at IS
    'Reserved for I4 SLA clocks; nullable in I1b';
