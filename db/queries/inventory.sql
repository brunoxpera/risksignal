-- inventory: the cross-aggregate inventory statements of the WP-3.05
-- import commit (ARCH-003 §5, WP-3.05b / DEV-060). One query file per
-- table is the rule elsewhere (assets.sql, components.sql, ...); this
-- snapshot read deliberately spans assets and components — it is the
-- whole-inventory aggregate of the matching.rebuild dedupe key.

-- InventorySnapshot returns the ARCH-003 §5 inventory aggregates as
-- visible on the caller's transaction: the cheap, deterministic state
-- summary a matching.rebuild job's dedupe key is hashed from
-- "(count(assets), count(components), max(assets.updated_at),
-- max(components.updated_at), max(deactivated_at))" — captured when the
-- rebuild is enqueued, so any inventory mutation bumps it and the next
-- change enqueues a fresh rebuild (ADR-012: exactly one rebuild per
-- inventory state change; the outbox UQ (dedupe_key) holds for the whole
-- job lifetime). The commit use case calls this statement INSIDE its own
-- transaction after its upserts, so the captured snapshot is the
-- post-commit state — a commit that changes nothing enqueues nothing and
-- a commit that changed something derives a snapshot that differs from
-- every earlier enqueue (its clock stamp advances the max updated_at).
-- max(deactivated_at) spans both tables (GREATEST): deactivation is a
-- lifecycle mutation of either aggregate that must also bump the hash.
-- Counts are bigint, the maxima nullable timestamptz (NULL on an empty
-- table).
-- name: InventorySnapshot :one
SELECT
    (SELECT count(*) FROM assets)      AS assets_count,
    (SELECT count(*) FROM components)  AS components_count,
    (SELECT max(updated_at) FROM assets)::timestamptz     AS assets_max_updated_at,
    (SELECT max(updated_at) FROM components)::timestamptz AS components_max_updated_at,
    GREATEST(
        (SELECT max(deactivated_at) FROM assets)::timestamptz,
        (SELECT max(deactivated_at) FROM components)::timestamptz
    )::timestamptz AS max_deactivated_at;
