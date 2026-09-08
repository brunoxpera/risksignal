-- Anchor query for the sqlc toolchain (WP-1a.05, ADR-009).
--
-- A deliberately trivial single-row SELECT. It pins the generation pipeline
-- (make generate must produce code from it) and will back the database half
-- of the readiness check in WP-1a.07: a healthy database always answers 1.

-- name: HealthCheck :one
SELECT 1;
