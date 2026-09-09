-- assets seed write (ARCH-001 §1, WP-1b.05 demo seed).

-- UpsertAsset inserts or refreshes an inventory asset by its natural key
-- (source, external_id) and returns its id: the demo seed must be
-- idempotent, so seeding twice yields no duplicates. created_at stays the
-- original registration time; the refresheable fields follow the seed data.
-- name: UpsertAsset :one
INSERT INTO assets (external_id, source, type, name, environment, criticality, exposure, owner)
VALUES (@external_id, @source, @type, @name, @environment, @criticality, @exposure, @owner)
ON CONFLICT (source, external_id) DO UPDATE SET
    type        = EXCLUDED.type,
    name        = EXCLUDED.name,
    environment = EXCLUDED.environment,
    criticality = EXCLUDED.criticality,
    exposure    = EXCLUDED.exposure,
    owner       = EXCLUDED.owner
RETURNING id;
