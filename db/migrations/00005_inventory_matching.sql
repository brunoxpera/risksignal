-- 00005_inventory_matching.sql — I3 inventory & matching schema, Expand
-- phase (ARCH-003, WP-3.02 / DEV-045, DEV-055).
--
-- Extends the I1b/I2 schema (migrations 00002/00003/00004) for iteration
-- I3, inventory & matching. Every change is an extension — nothing is
-- renamed, no I1b/I2 column or constraint changes meaning — so the schema
-- stays forward-only (ADR-010). The components extension follows
-- Expand-Migrate-Contract (implementation concept ch. 7.4): this
-- migration is the Expand phase — comparison keys and natural_key arrive
-- nullable and the legacy rows are backfilled — while the pre-I3
-- 4-column InsertComponent write path stays live. The Contract phase
-- (SET NOT NULL on the comparison keys and natural_key + the identifier
-- CHECK) is migration 00006 (DEV-046), applied together with the switch
-- to the I3 write path:
--   * assets:  updated_at / deactivated_at / verified_at (lifecycle,
--              ARCH-003 §1.1); UQ (source, external_id) unchanged;
--   * components: cpe/purl/image/digest originals, vendor_norm/
--     product_norm/version_norm comparison keys (nullable in the Expand
--     phase), version_scheme, natural_key (nullable), updated_at/
--     deactivated_at (ARCH-003 §1.2); the version_scheme CHECK enumerates
--     all seven domain values (version.go); the I1b plain (vendor, product)
--     index is replaced by the inventory product index (vendor_norm,
--     product_norm) (ADR-012, ARCH-003 §4); UQ (asset_id, natural_key) is
--     the import idempotency key;
--   * alias_rules / decision_rules: versioned, auditable matching config
--     (ARCH-003 §1.4, ch. 7.1, ADR-015) — priority_rules is deliberately
--     NOT created here (I4);
--   * matches: reasons / decision_rule_id / auto_method / auto_confidence /
--     auto_score (ADR-015 — decision rules survive matching.rebuild);
--     UQ (vulnerability_id, component_id, rule_version) unchanged;
--   * epss_history: append-only per-day history (ADR-013, ARCH-003 §7),
--     no foreign key onto epss_current (ADR-013: the current set is
--     TRUNCATE + COPY loaded and must stay unfettered).
--
-- Legacy rows: I1b/I2 components carry only vendor/product/version. They
-- are backfilled with safe defaults — trim + lowercase comparison keys
-- (the write-time norm minus NFKC, which the application layer owns from
-- WP-3.04 on), version_scheme 'unknown' (no ordering fabrications) and a
-- deterministic placeholder natural key derived from their identity. The
-- md5 here is a backfill discriminator only: the domain's sha-256
-- derivation (internal/domain/naturalkey.go) is not available in SQL, and
-- rows written through the I3 path from 00005 on always carry a proper
-- application-derived key (rows written through the still-live pre-I3
-- InsertComponent leave the keys NULL until DEV-046 switches the write
-- path — the columns stay nullable in this Expand phase). Identical
-- legacy components under one asset would violate UQ (asset_id,
-- natural_key) and abort the migration loudly instead of silently merging
-- duplicate inventory.
--
-- No Down migration: migrations are forward-only (implementation concept
-- ch. 7.4); rollbacks run the previous application image, not SQL.

-- +goose Up

-- assets extension (ARCH-003 §1.1). updated_at is stamped by the injected
-- clock on upsert and drives the inventory_snapshot hash of §5; the DB
-- default now() is the backstop for pre-I3 writes, exactly like created_at
-- (the import commits its clock-stamped value explicitly). deactivated_at
-- is the soft-deactivation lifecycle ("never delete — deactivated assets
-- stay historically referenceable", ch. 6.1); verified_at records the last
-- manual data-quality verification (ch. 11.1), informational in I3 and
-- audited (ch. 13.2). UQ (source, external_id) keeps its idempotency role
-- unchanged: a repeated import upserts, never duplicates.
ALTER TABLE assets
    ADD COLUMN updated_at     timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN deactivated_at timestamptz NULL,
    ADD COLUMN verified_at    timestamptz NULL;

COMMENT ON COLUMN assets.updated_at IS
    'Last inventory update from the injected clock (upsert-stamped; default now() backstop for pre-I3 writes) — drives the inventory_snapshot hash (ARCH-003 §5)';
COMMENT ON COLUMN assets.deactivated_at IS
    'Soft-deactivation time (ch. 6.1): NULL while active — deactivated assets stay historically referenceable, never deleted';
COMMENT ON COLUMN assets.verified_at IS
    'Last manual data-quality verification (ch. 11.1); informational in I3, audited (ch. 13.2); NULL until the first verification';

-- components extension (ARCH-003 §1.2/§1.3/§4) — Expand phase. Raw
-- originals are preserved verbatim (cpe/purl/image/digest nullable;
-- vendor/product/version stay NOT NULL as in I1b) while the normalised
-- comparison keys (vendor_norm/product_norm/version_norm, NFKC + trim +
-- lowercase at write time, no alias — aliases resolve at match time) and
-- the inferred version_scheme are stored separately (ch. 9.1
-- "Originalwerte bleiben erhalten"). natural_key is the deterministic
-- import idempotency key (UQ (asset_id, natural_key), §1.3). The new
-- comparison-key columns and natural_key are added nullable and
-- backfilled with safe defaults for the pre-I3 rows; they stay nullable
-- through this migration so the still-live pre-I3 4-column InsertComponent
-- keeps working — SET NOT NULL and the identifier CHECK are the Contract
-- phase of migration 00006 (DEV-046), applied together with the switch to
-- the I3 write path. version_scheme and updated_at are NOT NULL with DB
-- defaults, so the pre-I3 write path never touches them.
ALTER TABLE components
    ADD COLUMN cpe            text        NULL,
    ADD COLUMN purl           text        NULL,
    ADD COLUMN image          text        NULL,
    ADD COLUMN digest         text        NULL,
    ADD COLUMN vendor_norm    text        NULL,
    ADD COLUMN product_norm   text        NULL,
    ADD COLUMN version_norm   text        NULL,
    ADD COLUMN version_scheme text        NOT NULL DEFAULT 'unknown',
    ADD COLUMN natural_key    text        NULL,
    ADD COLUMN updated_at     timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN deactivated_at timestamptz NULL;

-- Safe default backfill of the pre-I3 rows (I1b/I2 components carry only
-- vendor/product/version): the comparison keys are the trim + lowercase
-- fold of the originals (legacy rows were ASCII demo/dev data; full NFKC
-- normalisation is the WP-3.04 application-layer function, applied to all
-- rows from 00005 on), version_scheme stays 'unknown' — a legacy version
-- gets no fabricated ordering — and natural_key is a deterministic
-- placeholder over the same identity the domain would hash (vendor,
-- product, version), md5-tagged 'legacy:' so it can never collide with
-- the 64-hex sha-256 keys the application derives. Each part is
-- length-prefixed so two identities can never concatenate into the same
-- input (the domain's NUL separators are unavailable in SQL text —
-- PostgreSQL rejects NUL bytes).
UPDATE components
   SET vendor_norm  = lower(btrim(vendor)),
       product_norm = lower(btrim(product)),
       natural_key  = 'legacy:' || md5(
           length(btrim(vendor))::text || ':' || lower(btrim(vendor)) || ',' ||
           length(btrim(product))::text || ':' || lower(btrim(product)) || ',' ||
           length(version)::text || ':' || version
       )
 WHERE vendor_norm IS NULL;

-- The version_scheme CHECK enumerates exactly the seven domain values of
-- internal/domain/version.go (semver/debian/rpm/maven/calver/generic/
-- unknown); 'unknown' is a first-class value — no ordering — never an
-- error (ARCH-003 §2). The identifier CHECK — a row must be matchable,
-- carrying at least one identity (cpe, purl, digest or image, image
-- included per DEV-044 reconciliation) or the vendor_norm/product_norm
-- pair — is deliberately NOT added here: it is the Contract phase of
-- migration 00006 (DEV-046) and must not reject the pre-I3 InsertComponent
-- writes that are still live until the write path switches.
ALTER TABLE components
    ADD CONSTRAINT components_version_scheme_check CHECK (
        version_scheme IN ('semver', 'debian', 'rpm', 'maven', 'calver', 'generic', 'unknown')
    );

-- The inventory product index (ADR-012, ARCH-003 §4): UQ (asset_id,
-- natural_key) is the import idempotency key (§1.3); components_product_idx
-- on (vendor_norm, product_norm) replaces the I1b plain (vendor, product)
-- index (00002) and serves the candidate pre-filter semi-join;
-- components_asset_id_idx serves the asset -> components read
-- (GET /assets/{id}/components). The constraint/index names follow the
-- 00002/00003 naming (table_column_column_key / table_column_idx).
DROP INDEX components_vendor_product_idx;

ALTER TABLE components
    ADD CONSTRAINT components_asset_id_natural_key_key UNIQUE (asset_id, natural_key);

CREATE INDEX components_product_idx ON components (vendor_norm, product_norm);
CREATE INDEX components_asset_id_idx ON components (asset_id);

COMMENT ON COLUMN components.cpe IS
    'Original CPE 2.3 string, preserved verbatim (ch. 9.1); syntactically validated at import (ARCH-003 §2)';
COMMENT ON COLUMN components.purl IS
    'Original package URL, preserved verbatim; syntactically validated at import, its type hints the version scheme';
COMMENT ON COLUMN components.image IS
    'Original image reference registry/repository[:tag][@digest], preserved verbatim';
COMMENT ON COLUMN components.digest IS
    'Immutable digest (sha256:…), preserved verbatim; stronger than a mutable tag — ranks above image in the natural key';
COMMENT ON COLUMN components.vendor_norm IS
    'Normalised vendor comparison key (NFKC + trim + lowercase at write time, no alias — aliases resolve at match time, ARCH-003 §2)';
COMMENT ON COLUMN components.product_norm IS
    'Normalised product comparison key (NFKC + trim + lowercase at write time, no alias)';
COMMENT ON COLUMN components.version_norm IS
    'Normalised version for the chosen scheme (kept raw in version); NULL when absent or not normalisable';
COMMENT ON COLUMN components.version_scheme IS
    'Version ordering scheme: semver | debian | rpm | maven | calver | generic | unknown — inferred per component at import (purl type -> CPE -> explicit column); unknown has no ordering and demotes matching (ARCH-003 §2)';
COMMENT ON COLUMN components.natural_key IS
    'Deterministic import idempotency key (UQ asset_id, natural_key, ARCH-003 §1.3): sha-256 of the strongest identifier (cpe > purl > digest > image > vendor/product/version), prefix-tagged — legacy pre-I3 rows carry a ''legacy:'' md5 placeholder';
COMMENT ON COLUMN components.updated_at IS
    'Last inventory update from the injected clock (default now() backstop for pre-I3 writes)';
COMMENT ON COLUMN components.deactivated_at IS
    'Soft-deactivation time: NULL while active — components stay referenceable when deactivated (ARCH-003 §1.2)';

-- alias_rules — controlled vendor/product aliases (ch. 9.1, ARCH-003 §1.4,
-- ADR-015). One versioned, auditable rule per alias mapping; from_value/
-- to_value are already normalised (NFKC + trim + lowercase) at the
-- boundary. version is the monotonic ruleset version — UQ (scope,
-- from_value, version) — and the composite effective rule version is
-- derived from the alias and decision rule versions (RulesetVersion,
-- internal/domain/mapping.go: "a<alias.version>d<decision.version>"),
-- flowing into matches.rule_version and the matching.rebuild dedupe key.
-- created_at/updated_at come from the injected clock like the other
-- audited rows (00003 convention); disabled rules are inert, never
-- deleted.
CREATE TABLE alias_rules (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scope      text        NOT NULL,
    from_value text        NOT NULL,
    to_value   text        NOT NULL,
    version    integer     NOT NULL,
    enabled    boolean     NOT NULL DEFAULT true,
    reason     text        NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT alias_rules_scope_from_value_version_key UNIQUE (scope, from_value, version),
    CONSTRAINT alias_rules_scope_check CHECK (scope IN ('vendor', 'product'))
);

COMMENT ON TABLE alias_rules IS
    'Controlled vendor/product aliases (ch. 9.1, ARCH-003 §1.4): versioned auditable config; the alias closure resolves them at match time — never at write time';
COMMENT ON COLUMN alias_rules.scope IS
    'Alias target: vendor | product';
COMMENT ON COLUMN alias_rules.from_value IS
    'The alias/variant, already NFKC + trim + lowercase';
COMMENT ON COLUMN alias_rules.to_value IS
    'The canonical value, already NFKC + trim + lowercase';
COMMENT ON COLUMN alias_rules.version IS
    'Monotonic ruleset version; the composite effective rule version is a<alias.version>d<decision.version> (mapping.go)';
COMMENT ON COLUMN alias_rules.enabled IS
    'Disabled rules are inert (never deleted — audited config)';
COMMENT ON COLUMN alias_rules.reason IS
    'Human rationale (audited)';
COMMENT ON COLUMN alias_rules.updated_at IS
    'Last rule change from the injected clock (never the DB wall clock)';

-- decision_rules — manual match corrections and exclusions (ch. 9.2,
-- ARCH-003 §1.4, ADR-015) that must survive automatic recompute. An
-- exclude rule forces a visible no_match referencing the rule; an override
-- rule forces its action while the match preserves the raw computed triple
-- in auto_method/auto_confidence/auto_score. target_scope jsonb
-- {cve_id?, vendor?, product?, component_id?} is the applicability (an
-- empty field is a wildcard; at least one field set); action jsonb holds
-- the forced method (+ candidate similarity) of overrides. reason is
-- mandatory (an audited correction without rationale is not a correction),
-- actor_id the author. The validity window valid_from <= now < valid_until
-- (valid_until NULL = open-ended until revoked) and the explicit
-- revoked_at gate applicability; version is the monotonic ruleset version
-- of the UQ'd effective rule version above. priority_rules is deliberately
-- not created (I4).
CREATE TABLE decision_rules (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    type          text        NOT NULL,
    target_scope  jsonb       NOT NULL,
    action        jsonb       NULL,
    reason        text        NOT NULL,
    actor_id      text        NOT NULL,
    valid_from    timestamptz NULL,
    valid_until   timestamptz NULL,
    version       integer     NOT NULL,
    revoked_at    timestamptz NULL,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    CONSTRAINT decision_rules_type_check CHECK (type IN ('exclude', 'override'))
);

COMMENT ON TABLE decision_rules IS
    'Manual match corrections and exclusions (ch. 9.2, ARCH-003 §1.4, ADR-015): auditable, versioned rules that survive matching.rebuild — matched rows reference the rule via matches.decision_rule_id';
COMMENT ON COLUMN decision_rules.type IS
    'exclude (forces no_match) | override (forces method/confidence/score, computed starting point preserved in matches.auto_*)';
COMMENT ON COLUMN decision_rules.target_scope IS
    'Applicability {cve_id?, vendor?, product?, component_id?}; empty field = wildcard, at least one field must be set';
COMMENT ON COLUMN decision_rules.action IS
    'Forced outcome of an override {method, similarity?}; NULL for exclude';
COMMENT ON COLUMN decision_rules.reason IS
    'Mandatory human rationale (ch. 9.2 — an audited correction without rationale is not a correction)';
COMMENT ON COLUMN decision_rules.actor_id IS
    'Author of the rule (audited)';
COMMENT ON COLUMN decision_rules.valid_from IS
    'Validity window start; NULL = no lower bound';
COMMENT ON COLUMN decision_rules.valid_until IS
    'Validity window end; NULL = open-ended until revoked (ch. 9.2 "bis sie abgelaufen oder aufgehoben ist")';
COMMENT ON COLUMN decision_rules.version IS
    'Monotonic ruleset version; the composite effective rule version is a<alias.version>d<decision.version> (mapping.go)';
COMMENT ON COLUMN decision_rules.revoked_at IS
    'Explicit revocation time; NULL while the rule stands';
COMMENT ON COLUMN decision_rules.updated_at IS
    'Last rule change from the injected clock (never the DB wall clock)';

-- matches extension (ARCH-003 §3, ADR-015): reasons is the auditable
-- TR-007 rationale list (jsonb, NOT NULL, '[]' for purely computed rows);
-- decision_rule_id references the rule that produced the match (an
-- exclusion or an override — NULL for purely computed matches);
-- auto_method/auto_confidence/auto_score preserve the raw computed triple
-- when a decision rule overrode it, so the override stays reversible
-- (ch. 9.3 "der berechnete Ausgangswert bleibt sichtbar"). The FK is
-- named explicitly like the 00002 FKs. UQ (vulnerability_id, component_id,
-- rule_version) is unchanged — it is what makes re-runs idempotent.
ALTER TABLE matches
    ADD COLUMN reasons          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN decision_rule_id uuid        NULL,
    ADD COLUMN auto_method      text        NULL,
    ADD COLUMN auto_confidence  text        NULL,
    ADD COLUMN auto_score       integer     NULL;

ALTER TABLE matches
    ADD CONSTRAINT matches_decision_rule_id_fkey FOREIGN KEY (decision_rule_id) REFERENCES decision_rules (id);

COMMENT ON COLUMN matches.reasons IS
    'Auditable rationale list of the match (TR-007, ARCH-003 §3): jsonb array, ''[]'' for purely computed rows';
COMMENT ON COLUMN matches.decision_rule_id IS
    'Decision rule that produced this match (exclusion or override, ADR-015); NULL = purely computed';
COMMENT ON COLUMN matches.auto_method IS
    'Raw computed method preserved when a decision rule overrode it; NULL otherwise';
COMMENT ON COLUMN matches.auto_confidence IS
    'Raw computed confidence preserved when a decision rule overrode it; NULL otherwise';
COMMENT ON COLUMN matches.auto_score IS
    'Raw computed score preserved when a decision rule overrode it; NULL otherwise';

-- epss_history — append-only EPSS history (ADR-013, ch. 8.4, ARCH-003 §7):
-- one row per (cve_id, observed_on), fed from the same EPSS run that
-- loads epss_current, only for the cve_ids with inventory relevance (the
-- candidate pre-filter set, §7), stamped observed_on = run date. The
-- natural key UQ (cve_id, observed_on) makes the daily append idempotent.
-- No foreign key onto epss_current (ADR-013): the current set is replaced
-- whole by TRUNCATE + COPY and must stay unfettered; history survives its
-- swaps by cve_id alone. score/percentile are the raw EPSS values in
-- [0,1]; model_version tags the scoring model/date of the observed day.
CREATE TABLE epss_history (
    cve_id        text        NOT NULL,
    observed_on   date        NOT NULL,
    score         numeric     NOT NULL,
    percentile    numeric     NOT NULL,
    model_version text        NOT NULL,
    CONSTRAINT epss_history_cve_id_observed_on_key UNIQUE (cve_id, observed_on)
);

COMMENT ON TABLE epss_history IS
    'Append-only EPSS history (ADR-013, ARCH-003 §7): per-day scores for inventory-relevant cve_ids, no FK onto epss_current — history must survive the current set''s TRUNCATE + COPY swaps';
COMMENT ON COLUMN epss_history.cve_id IS
    'CVE id, history key half';
COMMENT ON COLUMN epss_history.observed_on IS
    'Run date of the observed set, history key half — the daily append is idempotent on (cve_id, observed_on)';
COMMENT ON COLUMN epss_history.score IS
    'EPSS score, the probability in [0,1] the CVE is exploited, as observed that day';
COMMENT ON COLUMN epss_history.percentile IS
    'EPSS percentile in [0,1] of the score within the set, as observed that day';
COMMENT ON COLUMN epss_history.model_version IS
    'EPSS scoring model/date of the observed set, e.g. 2026-09-09';
